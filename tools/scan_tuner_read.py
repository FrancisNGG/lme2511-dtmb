#!/usr/bin/env python3
# 扫描 app 里读 tuner 增益(0x06/0x07/0x08)和 demod AGC(0x3e) 的地方
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

# 读函数候选: 0x1256d8, 0x127124, 0x12551c, 0x118a0c (读 reg 的)
read_fns = {0x1256d8:'read_fn_1256d8', 0x127124:'read_fn_127124', 0x12551c:'read_fn_12551c', 0x118a0c:'read_fn_118a0c'}

print("=== app 读 tuner 增益(0x06/0x07/0x08) 或 demod AGC(0x3e) 的位置 ===")
for idx, ins in enumerate(insns):
    if ins.mnemonic == 'bl' and ins.operands[0].imm in read_fns:
        w1 = backscan_w1(insns, idx)
        if w1 in (0x06, 0x07, 0x08, 0x3e, 0x3c, 0x3d, 0x3f):
            print(f"  0x{ins.address:08x}: {read_fns[ins.operands[0].imm]} reg 0x{w1:02x}")
