from .image_stream import ImageStream
from .parse_func import parse_func


def parse_pe64(file, dir_path):
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
        export_table[export_addr] = '%s.#%d.%s' % (
            _pe_name,
            export_ord,
            export_name,
        )

    import_table = dict()
    import_dll_idx = 0
    while True:
        vs.goto(data_dir_list[1][0] + 20 * import_dll_idx)
        _import_name_table = vs.read4()
        if _import_name_table == 0:
            break
        vs.skip(8)
        import_dll_name = vs.reads(vs.read4())
        _import_addr_base = vs.read4()
        import_idx = 0
        while True:
            vs.goto(_import_name_table + 8 * import_idx)
            _import_addr = _import_addr_base + 8 * import_idx
            val, flag = vs.read4s(2)
            if flag == 0:
                if val == 0:
                    break
                import_table[_import_addr] = (
                    '%s.%s' % (
                        import_dll_name,
                        vs.reads(val + 2),
                    )
                )
            else:
                import_table[_import_addr] = (
                    '%s.#%d' % (
                        import_dll_name,
                        val & 0x0000FFFF,
                    )
                )
            import_idx += 1
        import_dll_idx += 1

    image = vs
    func_visit = set()
    func_stack = list()

    with open(dir_path + "/imports.md", "w") as f:
        f.write("# Import Table\n")
        for addr, name in import_table.items():
            f.write("- 0x%08x = %s\n"  % (addr, name.split("@")[0]))

    with open(dir_path + "/exports.md", "w") as f:
        f.write("# Export Table\n")
        for addr, name in export_table.items():
            f.write("- [0x%08x](./func_0x%08x.md) = %s\n"  % (addr, addr, name.split("@")[0]))

    for func_addr in export_table:
        func_stack.append(func_addr)
        while func_stack:
            func_addr = func_stack.pop()
            if func_addr in func_visit:
                continue
            func_visit.add(func_addr)
            with open(dir_path + "/func_0x%08x.md" % func_addr, "w") as f:
                f.write("- Function 0x%08x" % func_addr)
                if func_addr in export_table:
                    f.write(" = %s" % export_table[func_addr])
                f.write("\n")
                f.write("- Goto [Entry](#flow-0x%08x)\n" % func_addr)
                for flow_addr, flow_item in parse_func(image, func_addr).items():
                    f.write("# Flow 0x%08x\n" % flow_addr)
                    f.write("- inbound:")
                    for in_addr in flow_item.inbounds:
                        f.write(" [0x%08x](#flow-0x%08x)" % (in_addr, in_addr))
                    f.write("\n")
                    f.write("- outbound:")
                    for out_addr in flow_item.outbounds:
                        f.write(" [0x%08x](#flow-0x%08x)" % (out_addr, out_addr))
                    f.write("\n")



    # def print_func(func_addr, func_name):
    #     func_set.add(func_addr)
    #     fp.write("# Function 0x%08x\n" % func_addr)
    #     fp.write("[(%s)](##flow-0x%08x)\n" % (func_name, func_addr))
    #     for addr, flow in parse_func(image, func_addr).items():
    #         fp.write("## Flow 0x%08x\n" % addr)
    #         fp.write("inbounds:")
    #         for in_addr in flow.inbounds:
    #             fp.write(" [0x%08x](##flow-0x%08x)" % (in_addr, in_addr))
    #         fp.write("\n")

    # for addr, name in export_table.items():
    #     print_func(addr, name.split("@")[0])


    # return vs, export_table, import_table
