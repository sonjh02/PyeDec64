from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from .image_stream import ImageStream


cs = Cs(CS_ARCH_X86, CS_MODE_64)


def parse_inst(image: ImageStream):
    pass
