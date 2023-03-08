from collections import namedtuple


Register = namedtuple("Register", "name")
MemoryPtr = namedtuple("MemoryPtr", ["addr", "size"])


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
    return Register(target_str)
