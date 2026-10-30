"""bring the migrated schema level with the models

Revision ID: a8b9c0d1e2f3
Revises: a7b8c9d0e1f2
Create Date: 2026-10-30

Until now the application's tables were created with Base.metadata.create_all(), and Alembic was only
used for some later additions. A database built purely from these migrations therefore lacked the audit
log, the wake-on-LAN tables, several user and machine columns, and had a users.role column that only
accepted ADMIN and ENGINEER. This revision adds whatever is missing. It looks before it changes
anything, so on a database that create_all() built (which already has all of this) it does nothing.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a8b9c0d1e2f3"
down_revision: Union[str, None] = "a7b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns(inspector, table):
    return {c["name"]: c for c in inspector.get_columns(table)}


def _add_missing(inspector, table, columns):
    have = _columns(inspector, table)
    for column in columns:
        if column.name not in have:
            op.add_column(table, column)


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())

    if "audit_logs" not in tables:
        op.create_table(
            "audit_logs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("actor_email", sa.String(255), nullable=False),
            sa.Column("action", sa.String(100), nullable=False),
            sa.Column("target", sa.String(255), nullable=True),
            sa.Column("result", sa.String(50), nullable=False, server_default="SUCCESS"),
            sa.Column("ip_address", sa.String(50), nullable=True),
            sa.Column("details", sa.JSON(), nullable=True),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_audit_logs_id", "audit_logs", ["id"])
        op.create_index("ix_audit_logs_actor_email", "audit_logs", ["actor_email"])
        op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
        op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])

    if "wol_requests" not in tables:
        op.create_table(
            "wol_requests",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("machine_id", sa.Integer(), sa.ForeignKey("machines.id", ondelete="CASCADE"), nullable=False),
            sa.Column("triggered_by", sa.String(255), nullable=False),
            sa.Column("mac_address", sa.String(17), nullable=False),
            sa.Column("broadcast_ip", sa.String(50), nullable=False, server_default="255.255.255.255"),
            sa.Column("port", sa.Integer(), nullable=False, server_default="9"),
            sa.Column("status", sa.String(30), nullable=False, server_default="REQUEST_CREATED"),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_wol_requests_id", "wol_requests", ["id"])
        op.create_index("ix_wol_requests_machine_id", "wol_requests", ["machine_id"])

    _add_missing(inspector, "machines", [
        sa.Column("mac_address", sa.String(17), nullable=True),
        sa.Column("wol_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("wol_port", sa.Integer(), nullable=False, server_default="9"),
        sa.Column("last_wol_request", sa.DateTime(timezone=True), nullable=True),
    ])
    if "ix_machines_mac_address" not in {i["name"] for i in inspector.get_indexes("machines")}:
        op.create_index("ix_machines_mac_address", "machines", ["mac_address"])

    _add_missing(inspector, "users", [
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("permissions", sa.JSON(), nullable=True),
        sa.Column("widget_permissions", sa.JSON(), nullable=True),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    ])

    # The original column was a database enum of ADMIN/ENGINEER; roles are plain text now (ADMIN, MANAGER,
    # OPERATOR, VIEWER, CUSTOM). Existing values keep their text; ENGINEER becomes OPERATOR, its equivalent.
    role = _columns(inspector, "users").get("role")
    if role is not None and isinstance(role["type"], sa.Enum):  # (Enum is a kind of String, so test for it first)
        op.alter_column("users", "role", existing_type=role["type"], type_=sa.String(50),
                        existing_nullable=False, postgresql_using="role::text")
        op.execute("UPDATE users SET role = 'OPERATOR' WHERE role = 'ENGINEER'")
        op.execute("DROP TYPE IF EXISTS userrole")


def downgrade() -> None:
    pass  # additive and idempotent: there is nothing safe to take away again
