from typing import Any

import numpy as np
from struct import unpack
from dataclasses import dataclass


@dataclass
class PE64:
    name: str
    image: bytes
    entry_addr: int
    export_dict: dict[int, str]
    import_dict: dict[int, str]
    section_dict: dict[bytes, tuple[int, int, int, int]]


def read2(b, p = 0):
    return unpack("H", b[p : p + 2])[0]


def read4(b, p = 0):
    return unpack("L", b[p : p + 4])[0]


def reads(b, p = 0):
    ret = ""
    while b[p]:
        assert 32 <= b[p] < 127, "Invalid Character"
        ret += chr(b[p])
        p += 1
    return ret


def open_pe64(file: str):
    with open(file, 'rb') as f:
        b_file = f.read()

    _pe_header_ptr = read4(b_file, 0x3c)

    _pe_header_sig = read4(b_file, _pe_header_ptr)
    assert _pe_header_sig == read4(b'PE\x00\x00'), "Invalid PE Header"

    section_cnt = read2(b_file, _pe_header_ptr + 6)

    _opt_header_sig = read2(b_file, _pe_header_ptr + 24)
    assert _opt_header_sig == 0x020b, "Invalid Optional Header (PE32+ Only)"

    entry_addr = read4(b_file, _pe_header_ptr + 40)
    _data_dir_cnt = read4(b_file, _pe_header_ptr + 132)
    assert _data_dir_cnt == 16, "Invalid Data Directory Entry Count"

    _export_table_addr = read4(b_file, _pe_header_ptr + 136)
    _import_table_addr = read4(b_file, _pe_header_ptr + 144)

    max_addr = 0
    section_dict = dict()
    for section_idx in range(section_cnt):
        base = _pe_header_ptr + 264 + section_idx * 40
        name = b_file[base : base + 8]
        info = tuple(read4(b_file, base + 8 + 4 * i) for i in range(4))
        section_dict[name] = info
        max_addr = max(max_addr, info[0] + info[1])

    v_imag = np.zeros(max_addr, "B")
    for vs, va, bs, ba in section_dict.values():
        sz = min(vs, bs)
        v_imag[va : va + sz] = np.frombuffer(b_file, "B", offset = ba)[:sz]
    b_imag = memoryview(v_imag).tobytes()

    _export_flags = read4(b_imag, _export_table_addr)
    assert _export_flags == 0, "Invalid Export Flags"

    _export_pe_name_addr = read4(b_imag, _export_table_addr + 12)
    _export_addr_table_size = read4(b_imag, _export_table_addr + 20)
    _export_name_ptr_cnt = read4(b_imag, _export_table_addr + 24)
    assert _export_addr_table_size == _export_name_ptr_cnt, "Invalid Export Size"
    _export_addr_table_addr = read4(b_imag, _export_table_addr + 28)
    _export_name_ptr_addr = read4(b_imag, _export_table_addr + 32)

    export_cnt = _export_addr_table_size
    export_pe_name = reads(b_imag, _export_pe_name_addr)
    export_dict = {entry_addr: "%s.!entry" % export_pe_name}
    for export_idx in range(export_cnt):
        addr = read4(b_imag, _export_addr_table_addr + export_idx * 8)
        _name_addr = read4(b_imag, _export_name_ptr_addr + export_idx * 4)
        name = reads(b_imag, _name_addr)
        export_dict[addr] = "%s.%s" % (export_pe_name, name)
    # for key, val in export_dict.items():
    #     print("[0x%08x] %s" % (key, val))

    import_dict = dict()
    _import_dll_idx = 0
    while True:
        dll_base = _import_table_addr + 20 * _import_dll_idx
        lookup_table_addr = read4(b_imag, dll_base)
        if lookup_table_addr == 0:
            break
        _dll_name_addr = read4(b_imag, dll_base + 12)
        dll_name  = reads(b_imag, _dll_name_addr)
        sym_addr_base = read4(b_imag, dll_base + 16)

        _import_sym_idx = 0
        while True:
            sym_base = lookup_table_addr + 8 * _import_sym_idx
            sym_addr = sym_addr_base + 8 * _import_sym_idx
            sym_name_addr = read4(b_imag, sym_base)
            sym_flag = read4(b_imag, sym_base + 4)
            if sym_flag:
                sym_ord = sym_name_addr & 0x0000FFFF
                import_dict[sym_addr] = "%s.#%d" % (dll_name, sym_ord)
            elif sym_name_addr:
                sym_name = reads(b_imag, sym_name_addr + 2)
                import_dict[sym_addr] = '%s.%s' % (dll_name, sym_name)
            else:
                break
            _import_sym_idx += 1
        _import_dll_idx += 1
    # for i in import_dict.items():
    #     print("[0x%08x] %s" % i)

    return PE64(
        export_pe_name,
        b_imag,
        entry_addr,
        export_dict,
        import_dict,
        section_dict,
    )
