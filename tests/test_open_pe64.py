from pyedec64 import open_pe64


def test_open_pe64():
    pe = open_pe64('./.dumps/test.dll')
