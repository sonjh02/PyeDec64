from struct import unpack
from bisect import bisect


class ImageStream():
    def __init__(self):
        self.ptr = 0
        self.addr_list = list()
        self.data_list = list()

    def add(self, addr, data):
        idx = bisect(self.addr_list, addr)
        assert (
            idx == 0
            or self.addr_list[idx-1] + len(self.data_list[idx-1]) <= addr
        )
        assert (
            idx == len(self.addr_list)
            or addr + len(data) <= self.addr_list[idx]
        )
        self.addr_list.insert(idx, addr)
        self.data_list.insert(idx, data)

    def read(self, size: int):
        idx = bisect(self.addr_list, self.ptr) - 1
        addr = self.addr_list[idx]
        data = self.data_list[idx]
        ret = data[self.ptr-addr:][:size]
        assert len(ret) == size
        self.ptr += size
        return ret

    def goto(self, addr: int):
        self.ptr = addr

    def skip(self, size: int):
        self.ptr += size

    def read1(self):
        return unpack('B', self.read(1))[0]

    def read1s(self, n = 1):
        return unpack('B' * n, self.read(n))

    def read2(self):
        return unpack('H', self.read(2))[0]

    def read2s(self, n = 1):
        return unpack('H' * n, self.read(2 * n))

    def read4(self):
        return unpack('L', self.read(4))[0]

    def read4s(self, n = 1):
        return unpack('L' * n, self.read(4 * n))

    def reads(self, addr: int, n=-1):
        ret = ""
        ret_addr = self.ptr
        self.goto(addr)
        while n != 0:
            b = self.read1()
            if b == 0:
                break
            assert 32 <= b < 127
            ret += chr(b)
            n -= 1
        self.goto(ret_addr)
        return ret
