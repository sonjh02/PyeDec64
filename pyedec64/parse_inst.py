from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from .image_stream import ImageStream


cs = Cs(CS_ARCH_X86, CS_MODE_64)


def parse_inst(image: ImageStream):
    offset: int = image.ptr
    code = b''
    for i in range(15):
        code += image.read(1)
        for inst in cs.disasm(code, offset):
            return (code, offset, inst.mnemonic, inst.op_str)
    raise ValueError((code, offset))
