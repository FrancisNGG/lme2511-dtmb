#!/usr/bin/env python3
# 扫描 app 里所有写 reg 0x00 的地方 (write_reg/rmw_reg 之前 mov w1,#0)
from capstone import *
from capstone.arm64 import *

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
TEXT_VA = 0xb6860
TEXT_SIZE = 0x11c700
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

insns = list(md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA))

def backscan_w1(insns, idx):
    for i in range(idx-1, max(idx-8,0), -1):
        ins = insns[i]
        if ins.mnemonic == 'mov' and ins.operands[0].reg == ARM64_REG_W1 and ins.operands[1].type == ARM64_OP_IMM:
            return ins.operands[1].imm
    return None

def backscan_w2(insns, idx):
    for i in range(idx-1, max(idx-8,0), -1):
        ins = insns[i]
        if ins.mnemonic == 'mov' and ins.operands[0].reg == ARM64_REG_W2 and ins.operands[1].type == ARM64_OP_IMM:
            return ins.operands[1].imm
    return None

print("=== app 写 reg 0x00 的位置 (write_reg w1=0) ===")
cnt = 0
for idx, ins in enumerate(insns):
    if ins.mnemonic == 'bl' and ins.operands[0].imm == 0x11887c:
        w1 = backscan_w1(insns, idx)
        if w1 == 0:
            w2 = backscan_w2(insns, idx)
            print(f"  0x{ins.address:08x}: write reg 0x00 = 0x{w2:02x}")
            cnt += 1
print(f"共 {cnt} 处写 reg 0x00")

print("\n=== app 写 reg 0x4e 的位置 (write_reg w1=0x4e) ===")
cnt = 0
for idx, ins in enumerate(insns):
    if ins.mnemonic == 'bl' and ins.operands[0].imm == 0x11887c:
        w1 = backscan_w1(insns, idx)
        if w1 == 0x4e:
            w2 = backscan_w2(insns, idx)
            print(f"  0x{ins.address:08x}: write reg 0x4e = 0x{w2:02x}")
            cnt += 1
print(f"共 {cnt} 处写 reg 0x4e")
