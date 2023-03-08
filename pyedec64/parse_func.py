from collections import namedtuple

from .parse_opnd import parse_opnd
from .parse_inst import parse_inst
from .image_stream import ImageStream


Inst = namedtuple("Inst", [
    'code',
    'addr',
    'mnemonic',
    'op_str',
    'depends',
    'affects',
    'clears',
    'links',
])


StateFlag = namedtuple("StateFlag", "name")


def parse_func(image: ImageStream):
    call_addr_list = list()
    branch_stack = list()
    inst_graph = dict()

    branch_stack.append(image.ptr)

    while branch_stack:
        image.goto(branch_stack.pop())
        while True:
            code, addr, mnemonic, op_str = inst_base = parse_inst(image)

            if addr in inst_graph:
                break

            inst_graph[addr] = inst = Inst(*inst_base, [], [], [], [])
            rip_addr = addr + len(code)

            if mnemonic == 'mov':
                dst, src = op_str.split(', ')
                inst.depends.append(parse_opnd(src, rip_addr))
                inst.affects.append(parse_opnd(dst, rip_addr))
                inst.links.append(rip_addr)
            # elif mnemonic == 'push':
            #     pass
            else:
                raise NotImplementedError(mnemonic)

            print(inst)
