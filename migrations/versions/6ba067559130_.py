"""empty message

Revision ID: 6ba067559130
Revises: 5d17ade6eaa5
Create Date: 2022-08-23 12:29:43.227982

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6ba067559130'
down_revision = '5d17ade6eaa5'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('form_2', schema=None) as batch_op:
        batch_op.add_column(sa.Column('land_proof', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('land_certificate', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('boq', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('difference', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('milestones', sa.String(), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('form_2', schema=None) as batch_op:
        batch_op.drop_column('milestones')
        batch_op.drop_column('difference')
        batch_op.drop_column('boq')
        batch_op.drop_column('land_certificate')
        batch_op.drop_column('land_proof')

    # ### end Alembic commands ###