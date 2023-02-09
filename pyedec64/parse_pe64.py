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
    rs.skip(16)
    assert rs.read2() == 0x020b
    rs.skip(14)

    entry_addr = rs.read4()

    rs.skip(88)

    data_dir_list = [
        rs.read4s(2)
        for _ in range(rs.read4())
    ]
    section_list = [
        (rs.read(8), *rs.read4s(4), rs.read(16))
        for _ in range(_section_cnt)
    ]

    vs = ImageStream()
    for _, vsize, vaddr, rsize, raddr, _ in section_list:
        rs.goto(raddr)
        data = rs.read(rsize)
        if vsize > rsize:
            data += b'\x00' * (vsize - rsize)
        vs.add(vaddr, data[:vsize])

    vs.goto(data_dir_list[0][0])
    assert vs.read4() == 0
    vs.skip(8)
    _pe_name = vs.reads(vs.read4())
    _ord_base = vs.read4()
    _export_cnt = vs.read4()
    assert _export_cnt == vs.read4()
    _export_addr_table = vs.read4()
    _export_name_table = vs.read4()
    _export_ord_table = vs.read4()

    export_table = {entry_addr: '%s.main' % _pe_name}
    for export_idx in range(_export_cnt):
        vs.goto(_export_addr_table + 8 * export_idx)
        export_addr = vs.read4()
        vs.goto(_export_name_table + 4 * export_idx)
        export_name = vs.reads(vs.read4())
        vs.goto(_export_ord_table + 2 * export_idx)
        export_ord = _ord_base + vs.read2()
        export_table[export_addr] = '%s.%d.%s' % (
            _pe_name,
            export_ord,
            export_name,
        )




    # import_table = dict()
