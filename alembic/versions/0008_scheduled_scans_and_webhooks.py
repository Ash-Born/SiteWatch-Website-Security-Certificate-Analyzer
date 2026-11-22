"""Add scheduled scans and per-user webhook notifications.

Revision ID: 0008_scheduled_scans_and_webhooks
Revises: 0007_bulk_scan_jobs
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0008_scheduled_scans_and_webhooks"
down_revision: Union[str, None] = "0007_bulk_scan_jobs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("webhook_url", sa.Text(), nullable=True))
    op.create_table(
        "scheduled_scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column("frequency_hours", sa.Integer(), nullable=False),
        sa.Column("last_run", sa.DateTime(), nullable=True),
        sa.Column("next_run", sa.DateTime(), nullable=False),
        sa.Column("is_active", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("last_status", sa.String(length=20), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scheduled_scans_id", "scheduled_scans", ["id"], unique=False)
    op.create_index("ix_scheduled_scans_user_id", "scheduled_scans", ["user_id"], unique=False)
    op.create_index("ix_scheduled_scans_next_run", "scheduled_scans", ["next_run"], unique=False)
    op.create_index("ix_scheduled_scans_is_active", "scheduled_scans", ["is_active"], unique=False)
    op.alter_column("scheduled_scans", "is_active", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_scheduled_scans_is_active", table_name="scheduled_scans")
    op.drop_index("ix_scheduled_scans_next_run", table_name="scheduled_scans")
    op.drop_index("ix_scheduled_scans_user_id", table_name="scheduled_scans")
    op.drop_index("ix_scheduled_scans_id", table_name="scheduled_scans")
    op.drop_table("scheduled_scans")
    op.drop_column("users", "webhook_url")
