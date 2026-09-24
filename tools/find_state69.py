#!/usr/bin/env python3
# 找 app 里写 state+0x69 (reg 0x0A 低4位 = BB_BIA + PD_TH) 的地方
from capstone import *
from capstone.arm64 import *

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
TEXT_VA = 0xb6860
TEXT_SIZE = 0x11c700
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# 找 strb wN, [xN, #0x69] 和 ldrb wN, [xN, #0x69] (state+0x69)
print("=== 读写 state+0x69 的位置 ===")
for ins in md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA):
    if ins.mnemonic in ('strb','ldrb','sturb','ldurb'):
        op = ins.op_str
        if '#0x69' in op or '#105' in op:
            print(f"  0x{ins.address:08x}: {ins.mnemonic} {op}")

# 找 0x1229bc 之前的 mov 立即数 (state+0x69 的来源)
print("\n=== 0x1229bc 附近上下文 (写 state+0x69) ===")
for ins in md.disasm(so[0x122940:0x1229c0], 0x122940):
    note = ""
    if ins.mnemonic in ('ldrb','strb','and','orr','mov','bfxil','sub','csel'):
        note = "  ;"
    print(f"  {ins.address:08x}: {ins.mnemonic} {ins.op_str}{note}")
