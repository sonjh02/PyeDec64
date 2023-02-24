from ..image_stream import ImageStream


def parse_modrm(op_size, prefix, image: ImageStream):
    ad_size = 0 if prefix[3] else 1

    byte = image.read1()
    bit_mode = byte >> 6
    bit_reg = (byte >> 3) & 7
    bit_rm = byte & 7

    if bit_mode == 3:
        raise NotImplementedError("ModRM.mode == 3")

    elif bit_rm == 4:
        byte = image.read1()
        bit_ss = byte >> 6
        bit_idx = (byte >> 3) & 7
        bit_base = byte & 7

        if bit_idx == 4:



    else:
        raise NotImplementedError("without sib")
