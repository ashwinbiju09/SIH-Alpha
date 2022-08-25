"""empty message

Revision ID: 04f09b8b0f10
Revises: 6ba067559130
Create Date: 2022-08-23 14:30:22.400846

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '04f09b8b0f10'
down_revision = '6ba067559130'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('form_3', schema=None) as batch_op:
        batch_op.add_column(sa.Column('scope', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('schematic_plan', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('proposed_method', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('fastrack', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('utilization_plan', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('economic_plan', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('integration', sa.String(), nullable=False))

    with op.batch_alter_table('form_4', schema=None) as batch_op:
        batch_op.add_column(sa.Column('need', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('excellence', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('estimation', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('benefits', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('equity', sa.String(), nullable=False))

    with op.batch_alter_table('form_5', schema=None) as batch_op:
        batch_op.add_column(sa.Column('maintanence', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('design', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('u_certificate', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('details', sa.String(), nullable=False))
        batch_op.add_column(sa.Column('proof', sa.String(), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('form_5', schema=None) as batch_op:
        batch_op.drop_column('proof')
        batch_op.drop_column('details')
        batch_op.drop_column('u_certificate')
        batch_op.drop_column('design')
        batch_op.drop_column('maintanence')

    with op.batch_alter_table('form_4', schema=None) as batch_op:
        batch_op.drop_column('equity')
        batch_op.drop_column('benefits')
        batch_op.drop_column('estimation')
        batch_op.drop_column('excellence')
        batch_op.drop_column('need')

    with op.batch_alter_table('form_3', schema=None) as batch_op:
        batch_op.drop_column('integration')
        batch_op.drop_column('economic_plan')
        batch_op.drop_column('utilization_plan')
        batch_op.drop_column('fastrack')
        batch_op.drop_column('proposed_method')
        batch_op.drop_column('schematic_plan')
        batch_op.drop_column('scope')

    # ### end Alembic commands ###
