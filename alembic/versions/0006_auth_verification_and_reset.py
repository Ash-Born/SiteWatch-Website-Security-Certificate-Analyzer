"""Add verification and one-time password reset fields.

Revision ID: 0006_auth_verification_and_reset
Revises: 0005_user_profile
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0006_auth_verification_and_reset"
down_revision: Union[str, None] = "0005_user_profile"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("is_verified", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("users", sa.Column("password_reset_token_hash", sa.String(length=64), nullable=True))
    op.add_column("users", sa.Column("password_reset_expires_at", sa.DateTime(), nullable=True))
    op.create_index("ix_users_is_verified", "users", ["is_verified"], unique=False)
    op.create_index("ix_users_password_reset_token_hash", "users", ["password_reset_token_hash"], unique=True)
    op.alter_column("users", "is_verified", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_users_password_reset_token_hash", table_name="users")
    op.drop_index("ix_users_is_verified", table_name="users")
    op.drop_column("users", "password_reset_expires_at")
    op.drop_column("users", "password_reset_token_hash")
    op.drop_column("users", "is_verified")
