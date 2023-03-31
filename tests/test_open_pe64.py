from pyedec64 import open_pe64


def test_open_pe64():
    pe = open_pe64('./.dumps/test.dll')
    print(pe.name)
    print(pe.entry_addr)
    print(pe.export_dict)
