from pyedec64 import open_pe64, parse_func


def test_open_pe64():
    pe = open_pe64('./.dumps/test.dll')
    print("Start")
    for key, val in pe.exports.items():
        if val[9:].startswith("?") and not val[9:].startswith("??"):
            try:
                print("Function 0x%08x = %s" % (key, val))
                flow_dict = parse_func(pe.image, key)
                for flow_addr, flow in flow_dict.items():
                    print("Flow 0x%08x" % flow_addr)
                    print("> inbounds:", repr(["0x%08x" % v for v in flow.inbounds]))
                    for inst in flow.codes:
                        print("> [0x%08x] %s" % (inst.addr, inst.asm))
                    print("> outbounds:", repr(["0x%08x" % v for v in flow.outbounds]))
                break
            except AssertionError as e:
                print(repr(e))
