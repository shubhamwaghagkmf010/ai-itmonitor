"""per-agent token, command expiry and requester, agents.manage permission

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-10-30

"""
import json
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b8c9d0e1f2a3"
down_revision: Union[str, None] = "a7b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("agent_token_hash", sa.String(64), nullable=True))
    op.add_column("agent_commands", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("agent_commands", sa.Column("requested_by", sa.String(255), nullable=True))

    # Deleting machines, changing a MAC and pushing updates moved from wol.manage to agents.manage.
    # Users with an explicit permission list keep what they could do before.
    users = sa.table("users", sa.column("id", sa.Integer), sa.column("permissions", sa.JSON))
    conn = op.get_bind()
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
