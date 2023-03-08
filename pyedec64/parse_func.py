from collections import namedtuple

from .parse_opnd import parse_opnd, Register, MemoryPtr, Immediate
from .parse_inst import parse_inst
from .image_stream import ImageStream


Inst = namedtuple("Inst", [
    'capstone',
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

            inst_graph[addr] = inst = Inst(mnemonic + ' ' + op_str, *inst_base, [], [], [], [])
            rip_addr = addr + len(code)
            rsp_opnd = Register('rsp', 8)
            of_opnd = StateFlag('OF')
            sf_opnd = StateFlag('SF')
            zf_opnd = StateFlag('ZF')
            af_opnd = StateFlag('AF')
            pf_opnd = StateFlag('PF')
            cf_opnd = StateFlag('CF')
            rax_opnd = Register('rax', 8)
            rcx_opnd = Register('rcx', 8)
            rdx_opnd = Register('rdx', 8)
            r8_opnd = Register('r8', 8)
            r9_opnd = Register('r9', 8)
            r10_opnd = Register('r10', 8)
            r11_opnd = Register('r11', 8)

            if mnemonic == 'mov':
                dst, src = op_str.split(', ')
                inst.depends.append(parse_opnd(src, rip_addr))
                inst.affects.append(parse_opnd(dst, rip_addr))
                inst.links.append(rip_addr)

            elif mnemonic == 'push':
                src_opnd = parse_opnd(op_str, rip_addr)
                size = (
                    len(code) - 1
                    if isinstance(src_opnd, Immediate)
                    else src_opnd.size
                )
                inst.depends.append(src_opnd)
                inst.affects.append(MemoryPtr('rsp + %d' % size, size))
                inst.affects.append(rsp_opnd)
                inst.links.append(rip_addr)

            elif mnemonic == 'pop':
                src_opnd = parse_opnd(op_str, rip_addr)
                size = src_opnd.size
                inst.affects.append(src_opnd)
                inst.affects.append(rsp_opnd)
                inst.links.append(rip_addr)

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

            elif mnemonic == 'cmp':
                dst, src = op_str.split(', ')
                inst.depends.append(parse_opnd(src, rip_addr))
                inst.depends.append(parse_opnd(dst, rip_addr))
                inst.affects.append(of_opnd)
                inst.affects.append(sf_opnd)
                inst.affects.append(zf_opnd)
                inst.affects.append(af_opnd)
                inst.affects.append(pf_opnd)
                inst.affects.append(cf_opnd)
                inst.links.append(rip_addr)

            elif mnemonic == 'test':
                dst, src = op_str.split(', ')
                src_opnd = parse_opnd(src, rip_addr)
                dst_opnd = parse_opnd(dst, rip_addr)
                inst.depends.append(src_opnd)
                inst.depends.append(dst_opnd)
                inst.affects.append(of_opnd)
                inst.affects.append(sf_opnd)
                inst.affects.append(zf_opnd)
                inst.clears.append(af_opnd)
                inst.affects.append(pf_opnd)
                inst.affects.append(cf_opnd)
                inst.links.append(rip_addr)

            elif mnemonic == 'jmp':
                try:
                    dest = int(op_str, 16) if op_str.startswith('0x') else int(op_str)
                except Exception:
                    raise NotImplementedError(op_str)
                inst.links.append(dest)
                branch_stack.append(dest)
                break

            elif mnemonic in ['jne', 'je']:
                dest = int(op_str, 16) if op_str.startswith('0x') else int(op_str)
                inst.depends.append(zf_opnd)
                inst.links.append(rip_addr)
                inst.links.append(dest)
                branch_stack.append(dest)

            elif mnemonic in ['jg', 'jng', 'jnle', 'jle']:
                dest = int(op_str, 16) if op_str.startswith('0x') else int(op_str)
                inst.depends.append(zf_opnd)
                inst.depends.append(sf_opnd)
                inst.depends.append(of_opnd)
                inst.links.append(rip_addr)
                inst.links.append(dest)
                branch_stack.append(dest)

            elif mnemonic == 'call':
                dest = 0
                try:
                    dest = int(op_str, 16) if op_str.startswith('0x') else int(op_str)
                except Exception:
                    raise NotImplementedError(op_str)
                inst.affects.append(rax_opnd)
                inst.clears.append(rcx_opnd)
                inst.clears.append(rdx_opnd)
                inst.clears.append(r8_opnd)
                inst.clears.append(r9_opnd)
                inst.clears.append(r10_opnd)
                inst.clears.append(r11_opnd)
                inst.links.append(rip_addr)
                call_addr_list.append(dest)

            else:
                print(call_addr_list)
                for key, val in inst_graph.items():
                    print(key, ':', val)
                raise NotImplementedError(mnemonic)
