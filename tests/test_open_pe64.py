from pyedec64 import open_pe64, parse_func


def test_open_pe64():
    pe = open_pe64('./.dumps/test.dll')
    parse_func(pe.image, pe.entry)
