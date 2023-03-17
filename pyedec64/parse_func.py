from collections import namedtuple

from .parse_inst import parse_inst
from .image_stream import ImageStream


Inst = namedtuple("Inst", ['asm', 'addr', 'hint', 'link', 'call'])
Flow = namedtuple("Flow", ['inst_list', 'inbounds', 'outbounds'])

_set_simple = {'mov', 'add', 'sub', 'xor', 'cmp', 'or', 'and', 'push', 'pop',
               'test', 'lea', 'nop', 'inc'}

_set_jcc = {'ja', 'jae', 'jb', 'jbe', 'jc', 'jcxz', 'jecxz', 'jrcxz', 'je',
            'jg', 'jge', 'jl', 'jle', 'jna', 'jnae', 'jnb', 'jnbe', 'jnc',
            'jne', 'jng', 'jnge', 'jnl', 'jnle', 'jno', 'jnp', 'jns', 'jo',
            'jp', 'jpe', 'jpo', 'js', 'jz'}

def _to_int(s):
    return int(s, 16) if s.startswith('0x') else int(s)

def _to_dest(s):
    try:
        return _to_int(s)
    except Exception:
        return s

def _rip_convert(op_str, rip):
    if op_str.count('[rip ') > 1:
        raise NotImplementedError('rip_convert: %s' % op_str)
    p = op_str.find('[rip ')
    if p == -1:
        return None, op_str
    q = op_str.find(']', p + 5)
    if q == -1:
        raise ValueError('rip_convert: %s' % op_str)
    if op_str[p+5] == '+':
        hint = rip + _to_int(op_str[p+7:q])
    elif op_str[p+5] == '-':
        hint = rip - _to_int(op_str[p+7:q])
    else:
        raise ValueError('rip_convert: %s' % op_str)
    op_str = "%s0x%x%s" % (op_str[:p+1], hint, op_str[q:])
    return hint, op_str

def parse_func(image: ImageStream, func_entry: int):

    branch_stack = list()
    inst_graph = dict()
    flow_entry_set = {func_entry}

    branch_stack.append(func_entry)
    while branch_stack:
        image.goto(branch_stack.pop())
        while True:
            code, addr, mnemonic, op_str = parse_inst(image)

            if addr in inst_graph:
                break

            rip = addr + len(code)
            hint, op_str = _rip_convert(op_str, rip)
            asm = mnemonic + ": " + op_str
            inst = inst_graph[addr] = Inst(asm, addr, hint, [], [])

            if mnemonic in _set_simple:
                inst.link.append(rip)

            elif mnemonic in _set_jcc:
                dest = _to_int(op_str)
                inst.link.append(rip)
                inst.link.append(dest)
                branch_stack.append(dest)
                flow_entry_set.add(dest)

            elif mnemonic == 'call':
                dest = _to_dest(op_str)
                inst.link.append(rip)
                inst.call.append(dest)

            elif mnemonic == 'jmp':
                dest = _to_dest(op_str)
                if type(dest) is not int:
                    raise NotImplementedError('Indirect jump')
                inst.link.append(dest)
                branch_stack.append(dest)
                flow_entry_set.add(dest)
                break

            elif mnemonic == 'ret':
                break

            else:
                raise NotImplementedError(mnemonic)

    flow_graph = dict()
    for flow_entry in flow_entry_set:
        while flow_entry not in flow_graph:
            flow = flow_graph[flow_entry] = Flow([], [], [])
            addr = flow_entry
            while True:
                if addr not in inst_graph:
                    raise ValueError(addr)
                if addr != flow_entry and addr in flow_entry_set:
                    flow.outbounds.append(addr)
                    flow_entry = addr
                    break
                inst = inst_graph[addr]
                flow.inst_list.append(inst)
                if len(inst.link) == 1:
                    addr = inst.link[0]
                else:
                    if inst.link:
                        flow_entry = inst.link[0]
                        flow.outbounds.extend(inst.link)
                    break

    for key, val in flow_graph.items():
        for addr in val.outbounds:
            flow_graph[addr].inbounds.append(key)

    return flow_graph
