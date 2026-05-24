"""initial schema — sessions, emails, attachments, hash_cache, sender_reputation, api_keys

Revision ID: 0001
Revises:
Create Date: 2026-05-25
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── scan_sessions ──
    op.create_table(
        "scan_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=True),
        sa.Column("triggered_by", sa.String(128), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("users_scanned", sa.Integer, server_default="0"),
        sa.Column("emails_scanned", sa.Integer, server_default="0"),
        sa.Column("attachments_scanned", sa.Integer, server_default="0"),
        sa.Column("block_count", sa.Integer, server_default="0"),
        sa.Column("quarantine_count", sa.Integer, server_default="0"),
        sa.Column("suspect_count", sa.Integer, server_default="0"),
        sa.Column("allow_count", sa.Integer, server_default="0"),
        sa.Column("error_count", sa.Integer, server_default="0"),
        sa.Column("notes", sa.Text, nullable=True),
    )
    op.create_index("ix_scan_sessions_source", "scan_sessions", ["source"])
    op.create_index("ix_scan_sessions_tenant_id", "scan_sessions", ["tenant_id"])
    op.create_index("ix_scan_sessions_started_at", "scan_sessions", ["started_at"])

    # ── email_analyses ──
    op.create_table(
        "email_analyses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(36),
                  sa.ForeignKey("scan_sessions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("message_id", sa.String(512), nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=True),
        sa.Column("mailbox_user", sa.String(255), nullable=True),
        sa.Column("subject_hash", sa.String(64), nullable=True),
        sa.Column("sender", sa.String(320), nullable=False),
        sa.Column("sender_domain", sa.String(255), nullable=False),
        sa.Column("reply_to", sa.String(320), nullable=True),
        sa.Column("spf_result", sa.String(16), nullable=True),
        sa.Column("dkim_result", sa.String(16), nullable=True),
        sa.Column("dmarc_result", sa.String(16), nullable=True),
        sa.Column("recipient_count", sa.Integer, server_default="1"),
        sa.Column("has_attachments", sa.Boolean, server_default=sa.false()),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("overall_verdict", sa.String(32), server_default="pending"),
        sa.Column("stage", sa.String(32), server_default="received"),
        sa.Column("risk_score", sa.Float, server_default="0"),
        sa.Column("analysis_time_ms", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_email_session_id", "email_analyses", ["session_id"])
    op.create_index("ix_email_message_id", "email_analyses", ["message_id"])
    op.create_index("ix_email_tenant_id", "email_analyses", ["tenant_id"])
    op.create_index("ix_email_mailbox_user", "email_analyses", ["mailbox_user"])
    op.create_index("ix_email_sender", "email_analyses", ["sender"])
    op.create_index("ix_email_sender_domain", "email_analyses", ["sender_domain"])
    op.create_index("ix_email_received_at", "email_analyses", ["received_at"])
    op.create_index("ix_email_created_at", "email_analyses", ["created_at"])
    op.create_index("ix_email_overall_verdict", "email_analyses", ["overall_verdict"])
    op.create_index("ix_email_received_verdict", "email_analyses",
                    ["received_at", "overall_verdict"])
    op.create_index("ix_email_tenant_received", "email_analyses",
                    ["tenant_id", "received_at"])

    # ── attachment_verdicts ──
    op.create_table(
        "attachment_verdicts",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("email_id", sa.String(36),
                  sa.ForeignKey("email_analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("sha1", sa.String(40), nullable=True),
        sa.Column("md5", sa.String(32), nullable=True),
        sa.Column("filename", sa.String(512), nullable=False),
        sa.Column("file_size", sa.BigInteger, server_default="0"),
        sa.Column("file_type", sa.String(16), server_default="other"),
        sa.Column("mime_type", sa.String(128), nullable=True),
        sa.Column("is_encrypted", sa.Boolean, server_default=sa.false()),
        sa.Column("is_macro_enabled", sa.Boolean, server_default=sa.false()),
        sa.Column("verdict", sa.String(32), server_default="pending"),
        sa.Column("confidence", sa.Float, server_default="0"),
        sa.Column("threat_name", sa.String(255), nullable=True),
        sa.Column("analysis_source", sa.String(32), server_default="pending"),
        sa.Column("signatures_matched", JSONB, server_default="[]"),
        sa.Column("heuristic_score", sa.Float, server_default="0"),
        sa.Column("yara_matches", JSONB, server_default="[]"),
        sa.Column("clamav_signature", sa.String(255), nullable=True),
        sa.Column("misp_score", sa.Float, server_default="0"),
        sa.Column("misp_events", JSONB, server_default="[]"),
        sa.Column("cape_score", sa.Float, server_default="0"),
        sa.Column("cape_task_id", sa.Integer, nullable=True),
        sa.Column("cape_report", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_attach_email_id", "attachment_verdicts", ["email_id"])
    op.create_index("ix_attach_sha256", "attachment_verdicts", ["sha256"])
    op.create_index("ix_attach_verdict", "attachment_verdicts", ["verdict"])
    op.create_index("ix_attach_threat_name", "attachment_verdicts", ["threat_name"])
    op.create_index("ix_attach_created_at", "attachment_verdicts", ["created_at"])
    op.create_index("ix_attach_sha256_verdict", "attachment_verdicts", ["sha256", "verdict"])
    op.execute(
        "CREATE INDEX ix_attach_cape_report_gin "
        "ON attachment_verdicts USING gin (cape_report jsonb_path_ops)"
    )

    # ── hash_cache ──
    op.create_table(
        "hash_cache",
        sa.Column("sha256", sa.String(64), primary_key=True),
        sa.Column("verdict", sa.String(32), nullable=False),
        sa.Column("threat_name", sa.String(255), nullable=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("confidence", sa.Float, server_default="0"),
        sa.Column("first_seen", sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
        sa.Column("hit_count", sa.Integer, server_default="1"),
        sa.Column("notes", sa.Text, nullable=True),
    )
    op.create_index("ix_hash_cache_verdict", "hash_cache", ["verdict"])

    # ── sender_reputation ──
    op.create_table(
        "sender_reputation",
        sa.Column("sender_domain", sa.String(255), primary_key=True),
        sa.Column("total_emails", sa.Integer, server_default="0"),
        sa.Column("blocked_count", sa.Integer, server_default="0"),
        sa.Column("allowed_count", sa.Integer, server_default="0"),
        sa.Column("risk_ratio", sa.Float, server_default="0"),
        sa.Column("is_whitelisted", sa.Boolean, server_default=sa.false()),
        sa.Column("is_blacklisted", sa.Boolean, server_default=sa.false()),
        sa.Column("last_updated", sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
    )

    # ── api_keys ──
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("key_hash", sa.String(255), nullable=False),
        sa.Column("key_prefix", sa.String(8), nullable=False),
        sa.Column("scopes", JSONB, server_default="[]"),
        sa.Column("is_active", sa.Boolean, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
    )
    op.create_index("ix_api_keys_key_prefix", "api_keys", ["key_prefix"])


def downgrade() -> None:
    op.drop_table("api_keys")
    op.drop_table("sender_reputation")
    op.drop_table("hash_cache")
    op.drop_table("attachment_verdicts")
    op.drop_table("email_analyses")
    op.drop_table("scan_sessions")
