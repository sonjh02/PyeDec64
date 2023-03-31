from pyedec64 import open_pe64, parse_func


def test_open_pe64():
    pe = open_pe64('./.dumps/test.dll')
    print("Start")
    for key, val in pe.exports.items():
        if val[9:].startswith("?") and not val[9:].startswith("??"):
            try:
                print(val)
                inst_dict = parse_func(pe.image, key)
                flag = False
                for key, val in inst_dict.items():
                    if type(val.far) is str and not val.link:
                        flag = True
                        break
                if flag:
                    break
            except AssertionError as e:
                print(repr(e))
