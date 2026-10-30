"""per-agent token, command expiry and requester, agents.manage permission

Revision ID: b8c9d0e1f2a3
Revises: a8b9c0d1e2f3
Create Date: 2026-10-30

"""
import json
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b8c9d0e1f2a3"
down_revision: Union[str, None] = "a8b9c0d1e2f3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(table: str, column: str) -> bool:
    # A database built by create_all() from the current models already has these columns; adding them
    # again would fail the whole upgrade.
    return column in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if not _has_column("machines", "agent_token_hash"):
        op.add_column("machines", sa.Column("agent_token_hash", sa.String(64), nullable=True))
    if not _has_column("agent_commands", "expires_at"):
        op.add_column("agent_commands", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    if not _has_column("agent_commands", "requested_by"):
        op.add_column("agent_commands", sa.Column("requested_by", sa.String(255), nullable=True))

    # Deleting machines, changing a MAC and pushing updates moved from wol.manage to agents.manage.
    # Users with an explicit permission list keep what they could do before.
    conn = op.get_bind()
    if "permissions" not in {c["name"] for c in sa.inspect(conn).get_columns("users")}:
        return  # nothing to carry over on a database without the column
    users = sa.table("users", sa.column("id", sa.Integer), sa.column("permissions", sa.JSON))
    for row in conn.execute(sa.select(users.c.id, users.c.permissions)).fetchall():
        perms = row.permissions
        if isinstance(perms, str):
            perms = json.loads(perms)
        if isinstance(perms, list) and "wol.manage" in perms and "agents.manage" not in perms:
            conn.execute(users.update().where(users.c.id == row.id).values(permissions=perms + ["agents.manage"]))


def downgrade() -> None:
    op.drop_column("agent_commands", "requested_by")
    op.drop_column("agent_commands", "expires_at")
    op.drop_column("machines", "agent_token_hash")
