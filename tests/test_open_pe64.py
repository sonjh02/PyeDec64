from pyedec64 import open_pe64, parse_func, parse_pe64


def test_run():
    pe = open_pe64('./.dumps/test.exe')
    print("Start")
    save_dir = './.dumps/test_exe'
    with open(save_dir + '/imports.txt', 'w') as f:
        for addr, name in pe.imports.items():
            f.write("[0x%08x] %s\n" % (addr, name))
    with open(save_dir + '/exports.txt', 'w') as f:
        for addr, name in pe.exports.items():
            f.write("[0x%08x] %s\n" % (addr, name))

    dfs_stack: list[int] = list()
    dfs_visit: set[int] = set()
    for func_addr, func_name in pe.exports.items():
        dfs_visit.add(func_addr)
        try:
            print("Function 0x%08x = %s" % (func_addr, func_name))
            flow_dict = parse_func(pe.image, func_addr)
            with open(save_dir + '/func_0x%08x.txt' % func_addr, 'w') as f:
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

    while dfs_stack:
        func_addr = dfs_stack.pop()
        if func_addr in dfs_visit:
            continue
        dfs_visit.add(func_addr)
        try:
            print("Function 0x%08x" % func_addr)
            flow_dict = parse_func(pe.image, func_addr)
            with open(save_dir + '/func_0x%08x.txt' % func_addr, 'w') as f:
                f.write("Function 0x%08x\n" % func_addr)
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
