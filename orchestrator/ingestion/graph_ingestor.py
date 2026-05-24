"""
Orchestrateur d'ingestion Graph API.

Pour chaque user du tenant :
  - récupère les messages (différentiel si `since` fourni)
  - pour chaque message avec pièces jointes :
      - télécharge les PJ (bytes)
      - calcule SHA256, mappe vers AnalysisRequest
      - appelle l'orchestrateur (pipeline complet)
      - persiste le résultat en DB
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from orchestrator.ingestion.graph_client import (
    GraphAttachment, GraphClient, GraphMessage, GraphUser,
)
from orchestrator.models.schemas import (
    AnalysisRequest, AnalysisResponse, AttachmentMetadata, EmailMetadata, FileType,
)
from orchestrator.services.orchestrator import OrchestratorService

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
#  Helpers : mapping Graph → schemas Pydantic
# ─────────────────────────────────────────────────────────────

_EXT_TO_FILETYPE: dict[str, FileType] = {
    "exe": FileType.EXE, "dll": FileType.DLL,
    "doc": FileType.DOC, "docx": FileType.DOCX, "docm": FileType.DOCM,
    "xls": FileType.XLS, "xlsx": FileType.XLSX, "xlsm": FileType.XLSM,
    "pdf": FileType.PDF,
    "zip": FileType.ZIP, "rar": FileType.RAR, "7z": FileType.SEVEN_Z,
    "js": FileType.JS, "vbs": FileType.VBS, "ps1": FileType.PS1, "bat": FileType.BAT,
    "lnk": FileType.LNK, "iso": FileType.ISO, "img": FileType.IMG, "hta": FileType.HTA,
}

_OFFICE_OPENXML_PREFIX = "PK"


def _filetype_from_name(filename: str) -> FileType:
    if "." not in filename:
        return FileType.OTHER
    ext = filename.rsplit(".", 1)[-1].lower()
    return _EXT_TO_FILETYPE.get(ext, FileType.OTHER)


def _is_encrypted_zip(content: bytes) -> bool:
    """Détection rapide d'un ZIP avec mot de passe (general purpose bit 0)."""
    if len(content) < 30 or not content.startswith(b"PK\x03\x04"):
        return False
    try:
        gp_flag = int.from_bytes(content[6:8], "little")
        return bool(gp_flag & 0x0001)
    except Exception:
        return False


def _detect_macros(filename: str, content: bytes) -> bool:
    """Heuristique simple : extension docm/xlsm OU OLE2 + 'vbaProject'."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in ("docm", "xlsm", "pptm"):
        return True
    if len(content) >= 4 and content[:4] == b"\xd0\xcf\x11\xe0":
        # OLE2 header — chercher signature macro
        return b"vbaProject" in content[:65536]
    return False


def _build_attachment_metadata(att: GraphAttachment, content: bytes) -> AttachmentMetadata:
    sha256 = hashlib.sha256(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()
    return AttachmentMetadata(
        filename=att.name[:512],
        file_size=len(content),
        sha256=sha256,
        sha1=sha1,
        md5=md5,
        mime_type=att.content_type,
        file_type=_filetype_from_name(att.name),
        is_encrypted=_is_encrypted_zip(content),
        is_macro_enabled=_detect_macros(att.name, content),
    )


def _build_analysis_request(
    message: GraphMessage,
    attachments: list[AttachmentMetadata],
    tenant_id: str,
    mailbox: str,
) -> AnalysisRequest:
    subject_hash = hashlib.sha256(message.subject.encode("utf-8", errors="ignore")).hexdigest()
    sender = message.sender_address or "unknown@unknown.invalid"
    domain = message.sender_domain or "unknown.invalid"
    return AnalysisRequest(
        agent_id=f"graph-ingestor:{tenant_id}",
        hospital_id=tenant_id,
        email=EmailMetadata(
            message_id=message.id,
            sender=sender,
            sender_domain=domain,
            recipient_count=message.recipient_count,
            subject_hash=subject_hash,
            received_at=message.received_at,
            has_attachments=True,
            spf_result=message.spf_result,
            dkim_result=message.dkim_result,
            dmarc_result=message.dmarc_result,
        ),
        attachments=attachments,
        request_deep_analysis=False,
    )


# ─────────────────────────────────────────────────────────────
#  Résultat d'ingestion
# ─────────────────────────────────────────────────────────────

@dataclass
class IngestionStats:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    users_scanned: int = 0
    emails_scanned: int = 0
    attachments_scanned: int = 0
    block_count: int = 0
    quarantine_count: int = 0
    suspect_count: int = 0
    allow_count: int = 0
    error_count: int = 0

    def record_verdict(self, response: AnalysisResponse) -> None:
        v = response.overall_verdict.value
        if v == "block":
            self.block_count += 1
        elif v == "quarantine":
            self.quarantine_count += 1
        elif v in ("suspect", "request_deep_analysis"):
            self.suspect_count += 1
        elif v == "allow":
            self.allow_count += 1
        elif v in ("error", "timeout"):
            self.error_count += 1


# ─────────────────────────────────────────────────────────────
#  Ingestor principal
# ─────────────────────────────────────────────────────────────

class GraphIngestor:
    """Boucle complète : Graph → pipeline → DB."""

    def __init__(
        self,
        graph: GraphClient,
        orchestrator: OrchestratorService,
        tenant_id: str,
        max_attachment_size: int = 50 * 1024 * 1024,
    ):
        self.graph = graph
        self.orchestrator = orchestrator
        self.tenant_id = tenant_id
        self.max_attachment_size = max_attachment_size

    async def scan_user_inbox(
        self,
        user: GraphUser,
        emails_per_user: int = 25,
        since: Optional[datetime] = None,
        stats: Optional[IngestionStats] = None,
    ) -> list[AnalysisResponse]:
        """Scanne une boîte. Retourne les réponses d'analyse."""
        mailbox_id = user.user_principal_name or user.id
        logger.info("Scan boîte : %s (top=%d, since=%s)", mailbox_id, emails_per_user, since)

        messages = await self.graph.list_user_messages(
            user.id, top=emails_per_user, since=since, only_with_attachments=True,
        )

        responses: list[AnalysisResponse] = []
        for msg in messages:
            try:
                response = await self._scan_message(user, msg, stats=stats)
                if response is not None:
                    responses.append(response)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Erreur scan message %s : %s", msg.id, exc)
                if stats:
                    stats.error_count += 1

        if stats:
            stats.emails_scanned += len(messages)

        return responses

    async def _scan_message(
        self,
        user: GraphUser,
        msg: GraphMessage,
        stats: Optional[IngestionStats] = None,
    ) -> Optional[AnalysisResponse]:
        """Télécharge les PJ d'un message et lance l'analyse."""
        mailbox = user.user_principal_name or user.id

        # Liste métadonnées PJ
        attachments = await self.graph.list_attachments(user.id, msg.id, include_inline=False)
        if not attachments:
            return None

        attachment_metas: list[AttachmentMetadata] = []
        attachment_bytes: dict[str, bytes] = {}

        for att in attachments:
            # Skip si trop gros (on garde l'info heuristique uniquement)
            if att.size > self.max_attachment_size:
                logger.info("PJ %s ignorée (taille=%d)", att.name, att.size)
                continue

            content = await self.graph.download_attachment(
                user.id, msg.id, att.id, max_size=self.max_attachment_size,
            )
            if content is None:
                continue

            meta = _build_attachment_metadata(att, content)
            attachment_metas.append(meta)
            attachment_bytes[meta.sha256] = content

            if stats:
                stats.attachments_scanned += 1

        if not attachment_metas:
            return None

        request = _build_analysis_request(msg, attachment_metas, self.tenant_id, mailbox)

        # Pipeline complet avec bytes disponibles → YARA + ClamAV inline
        response = await self.orchestrator.analyze_with_bytes(request, attachment_bytes)

        logger.info(
            "[%s] %s → verdict=%s score=%.2f (%dms)",
            mailbox, msg.subject[:60], response.overall_verdict.value,
            max((a.confidence for a in response.attachments), default=0.0),
            response.analysis_time_ms or 0,
        )

        if stats:
            stats.record_verdict(response)
        return response

    async def scan_tenant(
        self,
        emails_per_user: int = 25,
        max_users: int = 500,
        since: Optional[datetime] = None,
    ) -> IngestionStats:
        """Scan complet du tenant."""
        stats = IngestionStats()
        users = await self.graph.list_users(top=max_users)
        stats.users_scanned = len(users)

        for user in users:
            await self.scan_user_inbox(
                user, emails_per_user=emails_per_user, since=since, stats=stats,
            )

        stats.finished_at = datetime.now(timezone.utc)
        logger.info(
            "Scan tenant terminé — users=%d emails=%d attachments=%d "
            "block=%d quarantine=%d suspect=%d allow=%d errors=%d",
            stats.users_scanned, stats.emails_scanned, stats.attachments_scanned,
            stats.block_count, stats.quarantine_count, stats.suspect_count,
            stats.allow_count, stats.error_count,
        )
        return stats
