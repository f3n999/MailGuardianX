"""
Tests d'intégration de l'ingestion Graph API — Graph mocké.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from orchestrator.core.heuristics import HeuristicEngine
from orchestrator.ingestion.graph_client import GraphAttachment, GraphMessage, GraphUser
from orchestrator.ingestion.graph_ingestor import (
    GraphIngestor, _build_analysis_request, _build_attachment_metadata,
)
from orchestrator.models.schemas import Verdict
from orchestrator.services.orchestrator import OrchestratorService


@pytest.fixture
def orchestrator(mock_cache, mock_misp, mock_cape, mock_yara, mock_clamav):
    return OrchestratorService(
        cache=mock_cache, heuristic=HeuristicEngine(),
        misp=mock_misp, cape=mock_cape,
        yara=mock_yara, clamav=mock_clamav,
    )


def test_build_attachment_metadata_computes_sha256():
    content = b"some attachment content"
    att = GraphAttachment(
        id="att1", name="test.pdf", content_type="application/pdf",
        size=len(content), content_bytes=content,
    )
    meta = _build_attachment_metadata(att, content)
    assert meta.sha256 == hashlib.sha256(content).hexdigest()
    assert meta.file_size == len(content)
    assert meta.filename == "test.pdf"


def test_build_analysis_request_maps_correctly():
    msg = GraphMessage(
        id="msg1",
        subject="Test subject",
        received_at=datetime.now(timezone.utc),
        sender_address="user@example.com",
        sender_name="User",
        reply_to=None,
        recipient_count=2,
        has_attachments=True,
        body_preview="",
        spf_result="pass",
        dkim_result="pass",
        dmarc_result="pass",
    )
    from orchestrator.models.schemas import AttachmentMetadata, FileType
    att = AttachmentMetadata(
        filename="x.pdf", file_size=100, sha256="a" * 64, file_type=FileType.PDF,
    )
    request = _build_analysis_request(msg, [att], "tenant-1", "user@example.com")
    assert request.email.sender == "user@example.com"
    assert request.email.sender_domain == "example.com"
    assert request.email.recipient_count == 2
    assert len(request.attachments) == 1


@pytest.mark.asyncio
class TestGraphIngestor:
    async def test_scan_user_inbox_no_messages(self, orchestrator):
        graph = AsyncMock()
        graph.list_user_messages = AsyncMock(return_value=[])
        ingestor = GraphIngestor(graph, orchestrator, tenant_id="t1")

        user = GraphUser(id="u1", user_principal_name="u1@t.com", display_name="U1")
        responses = await ingestor.scan_user_inbox(user)
        assert responses == []

    async def test_scan_user_inbox_with_message_and_attachment(self, orchestrator):
        msg = GraphMessage(
            id="m1", subject="Hello", received_at=datetime.now(timezone.utc),
            sender_address="ok@hopital.fr", sender_name="OK",
            reply_to=None, recipient_count=1, has_attachments=True,
            body_preview="", spf_result="pass", dkim_result="pass", dmarc_result="pass",
        )
        att = GraphAttachment(
            id="a1", name="doc.pdf", content_type="application/pdf", size=1024,
        )
        content = b"%PDF-1.4 fake pdf bytes"

        graph = AsyncMock()
        graph.list_user_messages = AsyncMock(return_value=[msg])
        graph.list_attachments = AsyncMock(return_value=[att])
        graph.download_attachment = AsyncMock(return_value=content)

        ingestor = GraphIngestor(graph, orchestrator, tenant_id="t1")
        user = GraphUser(id="u1", user_principal_name="user@t.com", display_name="User")

        responses = await ingestor.scan_user_inbox(user)
        assert len(responses) == 1
        # Verdict probable : ALLOW (PDF normal, SPF pass)
        assert responses[0].overall_verdict in (Verdict.ALLOW, Verdict.REQUEST_DEEP_ANALYSIS)
