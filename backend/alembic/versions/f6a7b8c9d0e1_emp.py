"""add employee fields to assets

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'f6a7b8c9d0e1'
down_revision: Union[str, None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('assets', sa.Column('owned_by_emp_id', sa.String(length=80), nullable=True))
    op.add_column('assets', sa.Column('owned_by_emp_name', sa.String(length=160), nullable=True))
    op.add_column('assets', sa.Column('workstation_number', sa.String(length=80), nullable=True))


def downgrade() -> None:
    op.drop_column('assets', 'workstation_number')
    op.drop_column('assets', 'owned_by_emp_name')
    op.drop_column('assets', 'owned_by_emp_id')
