"""empty message

Revision ID: e69ece07b8b4
Revises: 591de2a36084
Create Date: 2022-08-25 16:43:05.661107

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e69ece07b8b4'
down_revision = '591de2a36084'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('funds', schema=None) as batch_op:
        batch_op.add_column(sa.Column('Amountsanctioned_s', sa.Integer(), nullable=False))
        batch_op.add_column(sa.Column('Amountreleased_s', sa.Integer(), nullable=False))
        batch_op.add_column(sa.Column('Amountsanctioned_o', sa.Integer(), nullable=False))
        batch_op.add_column(sa.Column('Amountreleased_o', sa.Integer(), nullable=False))
        batch_op.drop_column('Amountsanctioned')
        batch_op.drop_column('Amountreleased')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('funds', schema=None) as batch_op:
        batch_op.add_column(sa.Column('Amountreleased', sa.INTEGER(), nullable=False))
        batch_op.add_column(sa.Column('Amountsanctioned', sa.INTEGER(), nullable=False))
        batch_op.drop_column('Amountreleased_o')
        batch_op.drop_column('Amountsanctioned_o')
        batch_op.drop_column('Amountreleased_s')
        batch_op.drop_column('Amountsanctioned_s')

    # ### end Alembic commands ###