import os
import pytest
import graphviz
from collections import defaultdict
from pyedec64 import open_pe64, parse_func, reflow


@pytest.fixture(
    params=[
        ('./.dumps/test.dll', './.dumps/test_dll'),
        ('./.dumps/test.exe', './.dumps/test_exe'),
    ],
)
def target(request):
    return request.param


def test_run(target):
    pe_file, save_dir = target
    os.makedirs(save_dir, exist_ok=True)

    print("Start %s" % pe_file)
    pe = open_pe64(pe_file)

    with open(save_dir + '/_imports.txt', 'w') as f:
        for addr, name in pe.imports.items():
            f.write("[0x%08x] %s\n" % (addr, name))

    with open(save_dir + '/_exports.txt', 'w') as f:
        for addr, name in pe.exports.items():
            f.write("[0x%08x] %s\n" % (addr, name))

    with open(save_dir + '/_hexdata.txt', 'w') as f:
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

    dfs_stack: list[int] = list()
    dfs_visit: dict[int, tuple[dict[str, int], set[int]]] = dict()

    def write_func(func_addr: int, func_name: str | None = None):
        try:
            if func_name is None:
                print("Function 0x%08x" % func_addr)
            else:
                print("Function 0x%08x = %s" % (func_addr, func_name))

            flow_dict = parse_func(pe.image, func_addr)
            reflow(flow_dict)

            dot = graphviz.Digraph(name='func_0x%08x' % func_addr, comment=func_name)
            for flow_addr, flow in flow_dict.items():
                dot.node("0x%08x" % flow_addr)
            for flow_addr, flow in flow_dict.items():
                for outbound in flow.outbounds:
                    dot.edge("0x%08x" % flow_addr, "0x%08x" % outbound)
            dot.render(save_dir + '/func_0x%08x.gv' % func_addr)

            with open(save_dir + '/func_0x%08x.txt' % func_addr, 'w') as f:
                if func_name is None:
                    f.write("Function 0x%08x\n" % func_addr)
                else:
                    f.write("Function 0x%08x = %s\n" % (func_addr, func_name))

                for flow_addr, flow in sorted(flow_dict.items()):
                    f.write("\nFlow 0x%08x\n" % flow_addr)
                    f.write("> from:")
                    for v in flow.inbounds:
                        f.write(" 0x%08x" % v)
                    f.write("\n")
                    indent = 0
                    for inst in flow.codes:
                        if type(inst) == str:
                            f.write("> ")
                            if inst.startswith("BEGIN"):
                                f.write("  " * indent)
                                indent += 1
                            elif inst.startswith("END"):
                                indent -= 1
                                f.write("  " * indent)
                            else:
                                indent -= 1
                                f.write("  " * indent)
                                indent += 1
                            f.write(inst + "\n")
                        else:
                            f.write("> ")
                            f.write("  " * indent)
                            f.write("[0x%08x] %s" % (inst.addr, inst.asm))
                            if inst.near:
                                dfs_stack.append(inst.near)
                                f.write(" // Calling -")
                            if inst.far and type(inst.far) is int:
                                if inst.far in pe.imports:
                                    f.write(" // Calling %s" % pe.imports[inst.far])
                                else:
                                    f.write(" // Calling ??")
                            f.write("\n")

                            if inst.near:
                                dfs_visit[func_addr][1].add(inst.near)

                            if inst.far:
                                if type(inst.far) is int:
                                    if inst.far in pe.imports:
                                        dfs_visit[func_addr][0][pe.imports[inst.far].split(".")[0]] += 1
                                    else:
                                        dfs_visit[func_addr][0]["unknown"] += 1
                                else:
                                    dfs_visit[func_addr][0]["indirect"] += 1


                    f.write("> to:")
                    for v in flow.outbounds:
                        f.write(" 0x%08x" % v)
                    f.write("\n")
        except AssertionError as e:
            print(repr(e))

    for func_addr, func_name in pe.exports.items():
        if func_addr in dfs_visit:
            continue
        dfs_visit[func_addr] = (defaultdict(int), set())
        write_func(func_addr, func_name)

    while dfs_stack:
        func_addr = dfs_stack.pop()
        if func_addr in dfs_visit:
            continue
        dfs_visit[func_addr] = (defaultdict(int), set())
        write_func(func_addr)

    dot = graphviz.Digraph(name=pe.name)
    for func_addr, (calls, _) in dfs_visit.items():
        label = "func 0x%08x" % func_addr
        for call in calls.items():
            label += ", %s=%d" % call
        dot.node("func_0x%08x" % func_addr, label)
    for func_addr, (_, calls) in dfs_visit.items():
        for call_addr in calls:
            dot.edge("func_0x%08x" % func_addr, "func_0x%08x" % call_addr)
    dot.render(save_dir + '/%s.gv' % pe.name)
