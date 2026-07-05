"""add apps.frontend_url (optional, for the EndUsers password reset link)

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-05
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("apps", sa.Column("frontend_url", sa.String(500), nullable=True))


def downgrade() -> None:
    op.drop_column("apps", "frontend_url")
