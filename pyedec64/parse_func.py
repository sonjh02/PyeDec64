from iced_x86 import Decoder, Formatter, FormatterSyntax


formatter = Formatter(FormatterSyntax.INTEL)


def _parse_inst(image: bytes, addr: int):
    inst = Decoder(64, image[addr : addr + 15], ip=addr).decode()
    asm_str = formatter.format(inst)
    bytes_str = image[addr: addr + inst.len].hex().upper()

    print(addr)
    print(inst.ip)
    print(asm_str)
    print(bytes_str)
    print(inst.flow_control)



def parse_func(image: bytes, func_addr: int = 0):
    _parse_inst(image, func_addr)
