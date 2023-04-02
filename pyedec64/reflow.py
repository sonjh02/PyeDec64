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

def reflow(flow_dict: dict[int, Flow]):
    flag = True
    while flag:
        flag = False
        while try_simple_branch(flow_dict):
            flag = True
        while try_simple_block(flow_dict):
            flag = True
