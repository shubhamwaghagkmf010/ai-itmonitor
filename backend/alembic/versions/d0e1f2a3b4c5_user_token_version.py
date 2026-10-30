"""user token version (session revocation)

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
Create Date: 2026-10-30

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d0e1f2a3b4c5"
down_revision: Union[str, None] = "c9d0e1f2a3b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(table: str, column: str) -> bool:
    # A database built by create_all() from the current models already has these columns; adding them
    # again would fail the whole upgrade.
    return column in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    # Existing users start at 0, which is also what tokens issued before this change count as,
    # so nobody is signed out by the upgrade.
    if not _has_column("users", "token_version"):
        op.add_column("users", sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    op.drop_column("users", "token_version")
