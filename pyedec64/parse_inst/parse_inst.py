from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from importlib import import_module
from ..image_stream import ImageStream


_prefix_groups = [
    (0xF0, 0xF2),
    (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65),
    (0x66,),
    (0x67,),
    tuple(v for v in range(0x40, 0x50)),
]

_prefix_map = [None] * 256

for group, codes in enumerate(_prefix_groups):
    for code in codes:
        _prefix_map[code] = group

_dispatch_map = [None] * 256
cs = Cs(CS_ARCH_X86, CS_MODE_64)



def parse_inst(image: ImageStream):
    old_ptr = image.ptr
    prefix = [0] * 5
    while True:
        byte = image.read1()
        group = _prefix_map[byte]
        if group is None:
            break
        prefix[group] = byte
    if _dispatch_map[byte] is None:
        _dispatch_map[byte] = import_module(
            ".parse_op%02x" % byte,
            "pyedec64.parse_inst"
        ).parse
    _dispatch_map[byte](byte, prefix, image)

    new_ptr = image.ptr
    image.goto(old_ptr)
    raw_bytes = image.read(new_ptr - old_ptr)
    ref_inst = next(cs.disasm(raw_bytes, old_ptr))
    ref_asm = ref_inst.mnemonic + " " + ref_inst.op_str
    print(raw_bytes.hex(), ref_asm)
