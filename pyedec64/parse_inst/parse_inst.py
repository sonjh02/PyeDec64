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


def parse_inst(image: ImageStream):
    prefix = [None] * 5
    while True:
        byte = image.read1()
        print("b", byte)
        group = _prefix_map[byte]
        print("g", group)
        if group is None:
            break
        prefix[group] = byte
