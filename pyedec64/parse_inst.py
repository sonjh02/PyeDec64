from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from .image_stream import ImageStream


cs = Cs(CS_ARCH_X86, CS_MODE_64)


def parse_inst(image: ImageStream):
    addr: int = image.ptr
    code = b''
    for i in range(15):
        code += image.read(1)
        for inst in cs.disasm(code, addr):
            return (code, addr, inst.mnemonic, inst.op_str)
    raise ValueError((code, addr))
