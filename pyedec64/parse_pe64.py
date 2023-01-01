from .image_stream import ImageStream


def parse_pe64(file):
    rs = ImageStream()
    with open(file, 'rb') as f:
        rs.add(0, f.read())
    rs.goto(0x3c)
    rs.goto(rs.read4())
    assert rs.read(4) == b'PE\x00\x00'
    rs.skip(2)
    _section_cnt = rs.read2()
    rs.skip(12)
    _opt_header_size = rs.read2()
    rs.skip(2)
    assert rs.read2() == 0x020b
    rs.skip(14)

    entry_addr = rs.read4()

    rs.skip(88)

    data_dir_list = [rs.read4s(2) for _ in range(rs.read4())]
    section_list = [(rs.read(8), *rs.read4s(4), rs.read(16)) for _ in range(_section_cnt)]

    vs = ImageStream()
    for _, vsize, vaddr, rsize, raddr, _ in section_list:
        rs.goto(raddr)
        data = rs.read(rsize)
        if vsize > rsize:
            data += b'\x00' * (vsize - rsize)
