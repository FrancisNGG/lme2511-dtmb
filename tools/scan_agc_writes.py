#!/usr/bin/env python3
# 扫描 app 里所有写 AGC 环寄存器(0x38-0x4f)的位置和值
# write_reg @0x11887c(x0=dev,w1=reg,w2=val), rmw_reg @0x118e08(x0=dev,w1=reg,w2=clr,w3=set)
from capstone import *
from capstone.arm64 import *

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
TEXT_VA = 0xb6860
TEXT_SIZE = 0x11c700
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# 收集所有指令
insns = list(md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA))

def backscan_w1(insns, idx):
    """从 bl 往前找最近的 mov w1, #imm"""
    for i in range(idx-1, max(idx-8,0), -1):
        ins = insns[i]
        if ins.mnemonic == 'mov' and ins.operands[0].reg == ARM64_REG_W1 and ins.operands[1].type == ARM64_OP_IMM:
            return ins.operands[1].imm
        # w1 可能被其它指令覆盖
        if ins.mnemonic in ('bl','ret','b.') or (ins.mnemonic.startswith('b') and ins.mnemonic!='b.ne' and ins.mnemonic!='b.eq'):
            pass
    return None

def backscan_w2(insns, idx):
    for i in range(idx-1, max(idx-8,0), -1):
        ins = insns[i]
        if ins.mnemonic == 'mov' and ins.operands[0].reg == ARM64_REG_W2 and ins.operands[1].type == ARM64_OP_IMM:
            return ins.operands[1].imm
    return None

def backscan_w3(insns, idx):
    for i in range(idx-1, max(idx-8,0), -1):
        ins = insns[i]
        if ins.mnemonic == 'mov' and ins.operands[0].reg == ARM64_REG_W3 and ins.operands[1].type == ARM64_OP_IMM:
            return ins.operands[1].imm
    return None

print("=== 写 AGC 环寄存器 (reg 0x38-0x4f) 的位置 ===")
for idx, ins in enumerate(insns):
    if ins.mnemonic == 'bl' and ins.operands[0].imm in (0x11887c, 0x118e08):
        w1 = backscan_w1(insns, idx)
        if w1 is not None and 0x38 <= w1 <= 0x4f:
            fn = 'write' if ins.operands[0].imm == 0x11887c else 'rmw'
            w2 = backscan_w2(insns, idx)
            w3 = backscan_w3(insns, idx) if fn=='rmw' else None
            if fn == 'write':
                print(f"  0x{ins.address:08x}: {fn} reg 0x{w1:02x} = 0x{w2:02x}")
            else:
                print(f"  0x{ins.address:08x}: {fn} reg 0x{w1:02x} clr=0x{w2:02x} set=0x{w3:02x}")
