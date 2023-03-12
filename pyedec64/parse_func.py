from collections import namedtuple

from .parse_inst import parse_inst
from .image_stream import ImageStream


Inst = namedtuple("Inst", ['asm', 'addr', 'hint', 'link'])
CodeBlock = namedtuple("CodeBlock", ['inst_list', 'inbounds', 'outbounds'])
Func = namedtuple("Func", ['flow_graph', 'near_calls', 'far_calls'])

_set_simple = {'mov', 'add', 'sub', 'xor', 'cmp', 'or', 'and', 'push', 'pop',
               'test', 'lea'}

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

def parse_func(image: ImageStream):

    func_entry = image.ptr

    call_addr_list = list()
    branch_stack = list()
    inst_graph = dict()
    inbound_set = {func_entry}

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
            inst = inst_graph[addr] = Inst(asm, addr, hint, [])

            if mnemonic in _set_simple:
                inst.link.append(rip)

            elif mnemonic in _set_jcc:
                dest = _to_int(op_str)
                inst.link.append(dest)
                branch_stack.append(dest)
                inbound_set.add(dest)
                inst.link.append(rip)

            elif mnemonic == 'call':
                dest = _to_dest(op_str)
                call_addr_list.append(dest)
                inst.link.append(rip)

            elif mnemonic == 'jmp':
                dest = _to_dest(op_str)
                if type(dest) != int:
                    raise NotImplementedError('Indirect jump')
                inst.link.append(dest)
                branch_stack.append(dest)
                inbound_set.add(dest)
                break

            elif mnemonic == 'ret':
                break

            else:
                raise NotImplementedError(mnemonic)
