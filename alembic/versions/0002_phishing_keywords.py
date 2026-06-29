"""détection mots-clés phishing — keyword_score + keyword_categories sur email_analyses

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-29
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "email_analyses",
        sa.Column("keyword_score", sa.Float, server_default="0", nullable=False),
    )
    op.add_column(
        "email_analyses",
        sa.Column(
            "keyword_categories", JSONB,
            server_default=sa.text("'[]'::jsonb"), nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("email_analyses", "keyword_categories")
    op.drop_column("email_analyses", "keyword_score")
