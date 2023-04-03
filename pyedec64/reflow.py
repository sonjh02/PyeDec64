from .parse_func import Flow


def try_simple_block(flow_dict: dict[int, Flow]) -> bool:
    flag = False

    for flow_addr, flow in flow_dict.items():
        if len(flow.outbounds) != 1:
            continue
        flow_a_addr = flow.outbounds[0]
        flow_a = flow_dict[flow_a_addr]
        if flow_addr == flow_a_addr:
            continue
        if len(flow_a.inbounds) != 1:
            continue
        flag = True
        break

    if flag:
        flow_a = flow_dict.pop(flow_a_addr)
        flow.outbounds.clear()
        flow.outbounds.extend(flow_a.outbounds)
        for outbound in flow_a.outbounds:
            target = flow_dict[outbound].inbounds
            target.pop(target.index(flow_a_addr))
            target.append(flow_addr)
        flow.codes.extend(flow_a.codes)

    return flag


def try_simple_branch(flow_dict: dict[int, Flow]) -> bool:
    flag = False

    for flow_addr, flow in flow_dict.items():
        if len(flow.outbounds) != 2:
            continue
        if flow_addr in flow.outbounds:
            continue
        flow_a_addr, flow_b_addr = flow.outbounds
        flow_a = flow_dict[flow_a_addr]
        flow_b = flow_dict[flow_b_addr]
        if flow_a_addr in flow_b.outbounds:
            flow_b, flow_a = flow_a, flow_b
            flow_b_addr, flow_a_addr = flow_a_addr, flow_b_addr
        if len(flow_b.inbounds) != 2:
            continue
        if flow_a_addr not in flow_b.inbounds:
            continue
        if len(flow_a.inbounds) != 1:
            continue
        if len(flow_a.outbounds) != 1:
            continue
        if flow_a.outbounds[0] != flow_b_addr:
            continue
        flag = True
        break

    if flag:
        flow_a = flow_dict.pop(flow_a_addr)
        flow_b = flow_dict.pop(flow_b_addr)
        flow.outbounds.clear()
        flow.outbounds.extend(flow_b.outbounds)
        for outbound in flow_b.outbounds:
            target = flow_dict[outbound].inbounds
            target.pop(target.index(flow_b_addr))
            target.append(flow_addr)
        flow.codes.append("BEGIN IF")
        flow.codes.extend(flow_a.codes)
        flow.codes.append("END IF")
        flow.codes.extend(flow_b.codes)

    return flag


def try_normal_branch(flow_dict: dict[int, Flow]) -> bool:
    flag = False

    for flow_addr, flow in flow_dict.items():
        if len(flow.outbounds) != 2:
            continue
        if flow_addr in flow.outbounds:
            continue
        flow_a_addr, flow_b_addr = flow.outbounds
        flow_a = flow_dict[flow_a_addr]
        flow_b = flow_dict[flow_b_addr]
        if len(flow_a.inbounds) != 1:
            continue
        if len(flow_a.outbounds) != 1:
            continue
        if len(flow_b.inbounds) != 1:
            continue
        if len(flow_b.outbounds) != 1:
            continue
        flow_c_addr = flow_a.outbounds[0]
        if flow_c_addr != flow_b.outbounds[0]:
            continue
        if flow_c_addr in [flow_addr, flow_a_addr, flow_b_addr]:
            continue
        flow_c = flow_dict[flow_c_addr]
        if len(flow_c.inbounds) != 2:
            continue
        flag = True
        break

    if flag:
        flow_a = flow_dict.pop(flow_a_addr)
        flow_b = flow_dict.pop(flow_b_addr)
        flow_c = flow_dict.pop(flow_c_addr)
        flow.outbounds.clear()
        flow.outbounds.extend(flow_c.outbounds)
        for outbound in flow_c.outbounds:
            target = flow_dict[outbound].inbounds
            target.pop(target.index(flow_c_addr))
            target.append(flow_addr)
        flow.codes.append("BEGIN IF")
        flow.codes.extend(flow_a.codes)
        flow.codes.append("ELSE")
        flow.codes.extend(flow_b.codes)
        flow.codes.append("END IF")
        flow.codes.extend(flow_c.codes)

    return flag


def try_simple_loop(flow_dict: dict[int, Flow]) -> bool:
    flag = False

    for flow_addr, flow in flow_dict.items():
        if flow_addr not in flow.inbounds:
            continue
        if flow_addr not in flow.outbounds:
            continue
        flag = True
        break

    if flag:
        flow.inbounds.pop(flow.inbounds.index(flow_addr))
        flow.outbounds.pop(flow.outbounds.index(flow_addr))
        flow.codes.insert(0, "BEGIN LOOP")
        flow.codes.append("END LOOP")

    return flag


_try_list = [
    try_simple_block,
    try_simple_branch,
    try_normal_branch,
    try_simple_loop,
]


def reflow(flow_dict: dict[int, Flow]):
    flag = True
    while flag:
        flag = False
        for try_something in _try_list:
            while try_something(flow_dict):
                flag = True
