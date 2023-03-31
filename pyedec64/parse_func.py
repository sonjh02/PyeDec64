from dataclasses import dataclass
from iced_x86 import (
    Decoder,
    Formatter,
    FormatterSyntax,
    FlowControl,
    OpKind,
    Instruction,
    Register,
)


@dataclass
class Inst:
    asm: str
    raw: bytes
    far: int | str
    near: int
    link: list[int]


@dataclass
class Flow:
    code: list[Inst]
    inbounds: list[int]
    outbounds: list[int]


formatter = Formatter(FormatterSyntax.INTEL)


_near_branch_map = {
    OpKind.NEAR_BRANCH16: "near_branch16",
    OpKind.NEAR_BRANCH32: "near_branch32",
    OpKind.NEAR_BRANCH64: "near_branch64",
}


def _parse_near_branch(inst: Instruction) -> int:
    if inst.op0_kind in _near_branch_map:
        return getattr(inst, _near_branch_map[inst.op0_kind])
    raise NotImplementedError(('near branch', inst))


def _parse_indirect_branch(inst: Instruction, asm: str) -> int | str:
    if inst.op0_kind == OpKind.MEMORY and inst.memory_base == Register.RIP:
        return inst.ip_rel_memory_address
    return " ".join(asm.split(" ")[1:])


def _parse_inst(image: bytes, addr: int) -> Inst:
    inst = Decoder(64, image[addr : addr + 15], ip=addr).decode()
    next_addr = addr + inst.len
    raw = image[addr: next_addr]
    asm = formatter.format(inst)

    assert (
        inst.flow_control != FlowControl.EXCEPTION
    ), "Invalid Code: %s = %s" % (repr(inst), raw.hex().upper())

    if inst.flow_control == FlowControl.NEXT:
        return Inst(asm, raw, 0, 0, [next_addr])

    if inst.flow_control == FlowControl.UNCONDITIONAL_BRANCH:
        branch = _parse_near_branch(inst)
        return Inst(asm, raw, 0, 0, [branch])

    if inst.flow_control == FlowControl.INDIRECT_BRANCH:
        branch = _parse_indirect_branch(inst, asm)
        return Inst(asm, raw, branch, 0, [])

    if inst.flow_control == FlowControl.CONDITIONAL_BRANCH:
        branch = _parse_near_branch(inst)
        return Inst(asm, raw, 0, 0, [next_addr, branch])

    if inst.flow_control == FlowControl.RETURN:
        return Inst(asm, raw, 0, 0, [])

    if inst.flow_control == FlowControl.CALL:
        branch = _parse_near_branch(inst)
        return Inst(asm, raw, 0, branch, [next_addr])

    if inst.flow_control == FlowControl.INDIRECT_CALL:
        branch = _parse_indirect_branch(inst, asm)
        return Inst(asm, raw, branch, 0, [next_addr])

    if inst.flow_control == FlowControl.INTERRUPT:
        return Inst(asm, raw, 0, 0, [])

    raise NotImplementedError("FlowControl %d" % inst.flow_control)


def parse_func(image: bytes, func_addr: int = 0):
    inst_dict: dict[int, Inst] = dict()
    dfs_stack: list[int] = [func_addr]
    dfs_visit: set[int] = set()
    inbound_cnt: dict[int, int] = dict()
    while dfs_stack:
        addr = dfs_stack.pop()
        if addr in dfs_visit:
            continue
        dfs_visit.add(addr)
        inst_dict[addr] = inst = _parse_inst(image, addr)
        dfs_stack.extend(inst.link)
        for outbound in inst.link:
            inbound_cnt[outbound] += 1

    flow_dict: dict[int, Flow] = dict()
    dfs_stack: list[int] = [func_addr]
    dfs_visit: set[int] = set()
    while dfs_stack:
        addr = dfs_stack.pop()
        if addr in dfs_visit:
            continue
        dfs_visit.add(addr)
        flow_dict[addr] = flow = Flow([], [], [])




    return inst_dict
