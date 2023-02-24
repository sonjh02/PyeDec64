# 89/r = MOV reg to r/m
# default operand size = 32
# REX.R for R8-R15
# REX.W for 64 bit operands


from ..image_stream import ImageStream
from .parse_modrm import parse_modrm


def parse(_, prefix, image: ImageStream):
    op_size = 2 if (prefix[4] & 8) else 1 if prefix[2] else 0

    parse_modrm(op_size, prefix, image)
