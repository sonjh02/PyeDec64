from pyedec64 import open_pe64, parse_func, parse_pe64


def test_run():

    pe_file = './.dumps/test.dll'
    save_dir = './.dumps/test_dll'

    pe = open_pe64(pe_file)
    print("Start")

    with open(save_dir + '/imports.txt', 'w') as f:
        for addr, name in pe.imports.items():
            f.write("[0x%08x] %s\n" % (addr, name))

    with open(save_dir + '/exports.txt', 'w') as f:
        for addr, name in pe.exports.items():
            f.write("[0x%08x] %s\n" % (addr, name))

    with open(save_dir + '/imagehex.txt', 'w') as f:
        for o in range(0, len(pe.image), 16):
            f.write("[0x%08x]" % o)
            for i in range(16):
                f.write(" %02X" % pe.image[o + i])
            f.write(" | ")
            for i in range(16):
                v = pe.image[o + i]
                if 32 <= v < 127:
                    f.write("%s" % chr(v))
                else:
                    f.write(".")
            f.write("\n")

    def write_func(func_addr: int, func_name: str | None = None):
        try:
            if func_name is None:
                print("Function 0x%08x" % func_addr)
            else:
                print("Function 0x%08x = %s" % (func_addr, func_name))

            flow_dict = parse_func(pe.image, func_addr)

            with open(save_dir + '/func_0x%08x.txt' % func_addr, 'w') as f:
                if func_name is None:
                    f.write("Function 0x%08x\n" % func_addr)
                else:
                    f.write("Function 0x%08x = %s\n" % (func_addr, func_name))

                for flow_addr, flow in sorted(flow_dict.items()):
                    f.write("Flow 0x%08x\n" % flow_addr)
                    f.write("> from:")
                    for v in flow.inbounds:
                        f.write(" 0x%08x" % v)
                    f.write("\n")
                    for inst in flow.codes:
                        f.write("> [0x%08x] %s\n" % (inst.addr, inst.asm))
                        if inst.near:
                            dfs_stack.append(inst.near)
                        if inst.far and type(inst.far) is int:
                            if inst.far in pe.imports:
                                f.write("Calling %s\n" % pe.imports[inst.far])
                            else:
                                f.write("Calling ??\n")
                    f.write("> to:")
                    for v in flow.outbounds:
                        f.write(" 0x%08x" % v)
                    f.write("\n")
        except AssertionError as e:
            print(repr(e))

    dfs_stack: list[int] = list()
    dfs_visit: set[int] = set()
    for func_addr, func_name in pe.exports.items():
        dfs_visit.add(func_addr)
        write_func(func_addr, func_name)

    while dfs_stack:
        func_addr = dfs_stack.pop()
        if func_addr in dfs_visit:
            continue
        dfs_visit.add(func_addr)
        write_func(func_addr)
