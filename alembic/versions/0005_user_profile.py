"""Add editable profile fields.

Revision ID: 0005_user_profile
Revises: 0004_roles_activity
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0005_user_profile"
down_revision: Union[str, None] = "0004_roles_activity"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("full_name", sa.String(120), nullable=True))
    op.add_column("users", sa.Column("email", sa.String(254), nullable=True))
    op.add_column("users", sa.Column("avatar_filename", sa.String(80), nullable=True))
    op.create_index("ix_users_email", "users", ["email"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_email", table_name="users")
    op.drop_column("users", "avatar_filename")
    op.drop_column("users", "email")
    op.drop_column("users", "full_name")
