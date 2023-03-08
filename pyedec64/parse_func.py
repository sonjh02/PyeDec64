from collections import namedtuple

from .parse_opnd import parse_opnd, Register, MemoryPtr
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
            rsp_opnd = Register('rsp', 8)
            of_opnd = StateFlag('OF')
            sf_opnd = StateFlag('SF')
            zf_opnd = StateFlag('ZF')
            af_opnd = StateFlag('AF')
            pf_opnd = StateFlag('PF')
            cf_opnd = StateFlag('CF')

            if mnemonic == 'mov':
                dst, src = op_str.split(', ')
                inst.depends.append(parse_opnd(src, rip_addr))
                inst.affects.append(parse_opnd(dst, rip_addr))
                inst.links.append(rip_addr)
            elif mnemonic == 'push':
                src_opnd = parse_opnd(op_str, rip_addr)
                size = src_opnd.size
                inst.depends.append(src_opnd)
                inst.affects.append(MemoryPtr('rsp + %d' % size, size))
                inst.affects.append(rsp_opnd)
            elif mnemonic == 'sub' or mnemonic == 'add':
                dst, src = op_str.split(', ')
                inst.depends.append(parse_opnd(src, rip_addr))
                inst.affects.append(parse_opnd(dst, rip_addr))
                inst.affects.append(of_opnd)
                inst.affects.append(sf_opnd)
                inst.affects.append(zf_opnd)
                inst.affects.append(af_opnd)
                inst.affects.append(pf_opnd)
                inst.affects.append(cf_opnd)
                inst.links.append(rip_addr)
            else:
                raise NotImplementedError(mnemonic)

            print(inst)
