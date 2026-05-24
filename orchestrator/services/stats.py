"""
Service stats — requêtes PostgreSQL pour le dashboard SOC.

Remplace le placeholder de /api/v1/stats par de vraies données issues
des tables `email_analyses` et `attachment_verdicts`.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from orchestrator.models.database import AttachmentVerdict, EmailAnalysis, ScanSession
from orchestrator.models.schemas import DashboardStats

logger = logging.getLogger(__name__)


class StatsService:
    """Calcule les agrégats du dashboard depuis PostgreSQL."""

    def __init__(self, default_window_hours: int = 24):
        self.default_window_hours = default_window_hours

    async def compute(
        self,
        db: AsyncSession,
        window_hours: Optional[int] = None,
    ) -> DashboardStats:
        """
        Calcule les stats sur une fenêtre temporelle.
        Toutes les agrégations sont faites côté DB (pas de chargement complet).
        """
        hours = window_hours or self.default_window_hours
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours)

        # 1. Compteurs globaux par verdict
        verdict_counts = await self._verdict_counts(db, start)
        total = sum(verdict_counts.values())

        # 2. Temps moyen d'analyse
        avg_time = await self._avg_analysis_time(db, start)

        # 3. Top threats
        top_threats = await self._top_threats(db, start, limit=10)

        # 4. Top expéditeurs bloqués
        top_senders = await self._top_blocked_senders(db, start, limit=10)

        # 5. False positive rate (estimé : ratio whitelist sur blocks)
        false_positive_rate = await self._false_positive_estimate(db, start)

        return DashboardStats(
            total_analyzed=total,
            total_blocked=verdict_counts.get("block", 0),
            total_allowed=verdict_counts.get("allow", 0),
            total_quarantined=verdict_counts.get("quarantine", 0),
            total_pending=verdict_counts.get("pending", 0),
            false_positive_rate=round(false_positive_rate, 4),
            avg_analysis_time_ms=round(avg_time, 2),
            top_threats=top_threats,
            top_blocked_senders=top_senders,
            period_start=start,
            period_end=now,
        )

    # ────────── Queries internes ──────────

    async def _verdict_counts(
        self, db: AsyncSession, since: datetime
    ) -> dict[str, int]:
        stmt = (
            select(EmailAnalysis.overall_verdict, func.count(EmailAnalysis.id))
            .where(EmailAnalysis.created_at >= since)
            .group_by(EmailAnalysis.overall_verdict)
        )
        result = await db.execute(stmt)
        return {verdict: count for verdict, count in result.all()}

    async def _avg_analysis_time(self, db: AsyncSession, since: datetime) -> float:
        stmt = (
            select(func.avg(EmailAnalysis.analysis_time_ms))
            .where(EmailAnalysis.created_at >= since)
            .where(EmailAnalysis.analysis_time_ms.isnot(None))
        )
        result = await db.execute(stmt)
        avg = result.scalar()
        return float(avg) if avg is not None else 0.0

    async def _top_threats(
        self, db: AsyncSession, since: datetime, limit: int = 10
    ) -> list[dict]:
        stmt = (
            select(
                AttachmentVerdict.threat_name,
                func.count(AttachmentVerdict.id).label("count"),
            )
            .where(AttachmentVerdict.created_at >= since)
            .where(AttachmentVerdict.threat_name.isnot(None))
            .where(AttachmentVerdict.verdict.in_(["block", "quarantine"]))
            .group_by(AttachmentVerdict.threat_name)
            .order_by(func.count(AttachmentVerdict.id).desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        return [{"name": name, "count": count} for name, count in result.all()]

    async def _top_blocked_senders(
        self, db: AsyncSession, since: datetime, limit: int = 10
    ) -> list[dict]:
        stmt = (
            select(
                EmailAnalysis.sender_domain,
                func.count(EmailAnalysis.id).label("count"),
            )
            .where(EmailAnalysis.created_at >= since)
            .where(EmailAnalysis.overall_verdict.in_(["block", "quarantine"]))
            .group_by(EmailAnalysis.sender_domain)
            .order_by(func.count(EmailAnalysis.id).desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        return [{"domain": d, "count": c} for d, c in result.all()]

    async def _false_positive_estimate(
        self, db: AsyncSession, since: datetime
    ) -> float:
        """
        Approximation : ratio des hash en HashCache (source='whitelist')
        qui apparaissent aussi en BLOCK durant la fenêtre.
        Sans système de feedback, on retourne 0.0 (à raffiner).
        """
        return 0.0

    # ────────── Stats par tenant ──────────

    async def per_tenant(
        self, db: AsyncSession, tenant_id: str, window_hours: int = 24
    ) -> dict:
        """Stats spécifiques à un tenant M365."""
        start = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        stmt = (
            select(EmailAnalysis.overall_verdict, func.count(EmailAnalysis.id))
            .where(EmailAnalysis.tenant_id == tenant_id)
            .where(EmailAnalysis.created_at >= start)
            .group_by(EmailAnalysis.overall_verdict)
        )
        result = await db.execute(stmt)
        return {v: c for v, c in result.all()}

    # ────────── Stats sessions ──────────

    async def recent_sessions(
        self, db: AsyncSession, limit: int = 20
    ) -> list[dict]:
        stmt = (
            select(ScanSession)
            .order_by(ScanSession.started_at.desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        sessions = result.scalars().all()
        return [
            {
                "id": s.id,
                "source": s.source,
                "tenant_id": s.tenant_id,
                "started_at": s.started_at.isoformat(),
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
                "users_scanned": s.users_scanned,
                "emails_scanned": s.emails_scanned,
                "block_count": s.block_count,
                "quarantine_count": s.quarantine_count,
                "suspect_count": s.suspect_count,
                "allow_count": s.allow_count,
            }
            for s in sessions
        ]
