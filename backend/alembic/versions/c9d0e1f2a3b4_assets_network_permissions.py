"""assets.view / assets.manage / network.manage permissions

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-10-30

"""
import json
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c9d0e1f2a3b4"
down_revision: Union[str, None] = "b8c9d0e1f2a3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The asset register and network scans used to need only telemetry.view. Users with an explicit
    # permission list keep access: everyone who could view telemetry may view the register, and those
    # who administered agents may also manage it and run scans.
    conn = op.get_bind()
    if "permissions" not in {c["name"] for c in sa.inspect(conn).get_columns("users")}:
        return  # nothing to carry over on a database without the column
    users = sa.table("users", sa.column("id", sa.Integer), sa.column("permissions", sa.JSON))
    for row in conn.execute(sa.select(users.c.id, users.c.permissions)).fetchall():
        perms = row.permissions
        if isinstance(perms, str):
            perms = json.loads(perms)
        if not isinstance(perms, list):
            continue
        add = []
        if "telemetry.view" in perms:
            add.append("assets.view")
        if "wol.manage" in perms or "agents.manage" in perms:
            add += ["assets.manage", "network.manage"]
        add = [p for p in add if p not in perms]
        if add:
            conn.execute(users.update().where(users.c.id == row.id).values(permissions=perms + add))


def downgrade() -> None:
    pass  # unused permission names are harmless
