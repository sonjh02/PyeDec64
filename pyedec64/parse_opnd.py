from collections import namedtuple


Register = namedtuple("Register", ["name", "size"])
MemoryPtr = namedtuple("MemoryPtr", ["addr", "size"])
Immediate = namedtuple("Immediate", ["value"])


register_sizes = [
    (
        8,
        set(
            ['r' + v for v in ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp']]
            + ['r%d' % v for v in range(8, 16)]
        ),
    ),
    (
        4,
        set(
            ['e' + v for v in ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp']]
            + ['r%dd' % v for v in range(8, 16)]
        ),
    ),
    (
        2,
        set(
            ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp']
            + ['r%dw' % v for v in range(8, 16)]
        ),
    ),
    (
        1,
        set(
            [v + 'l' for v in 'abcd']
            + ['r%db' % v for v in range(8, 16)]
            + ['sil', 'dil', 'bpl', 'spl']
        ),
    ),
]


memory_sizes = [
    ('byte ptr ', 1),
    ('word ptr ', 2),
    ('dword ptr ', 4),
    ('qword ptr ', 8),
]


def parse_opnd(target_str: str, rip_addr: int):
    for prefix, size in memory_sizes:
        if target_str.startswith(prefix):
            assert target_str[len(prefix)] == '['
            assert target_str[-1] == ']'
            target_str = target_str[len(prefix)+1:-1]
            if target_str.startswith('rip + '):
                return MemoryPtr(rip_addr + int(target_str[6:]), size)
            if target_str.startswith('rip - '):
                return MemoryPtr(rip_addr - int(target_str[6:]), size)
            return MemoryPtr(target_str, size)

    for size, register_set in register_sizes:
        if target_str in register_set:
            return Register(target_str, size)

    if target_str.startswith('0x'):
        return Immediate(target_str)

    raise NotImplementedError(target_str)
