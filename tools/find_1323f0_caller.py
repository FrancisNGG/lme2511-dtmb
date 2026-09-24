#!/usr/bin/env python3
# 找 0x1323f0 函数(写 0x48=0) 的调用点, 理解调用时机
from capstone import *
from capstone.arm64 import *

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
TEXT_VA = 0xb6860
TEXT_SIZE = 0x11c700
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

print("=== bl 0x1323f0 的调用点 ===")
for ins in md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA):
    if ins.mnemonic == 'bl' and ins.operands[0].imm == 0x1323f0:
        print(f"  0x{ins.address:08x}")

print("\n=== bl 0x132a78 / 0x132c64 (0x1323f0 内的子调用) 的调用点 ===")
for ins in md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA):
    if ins.mnemonic == 'bl' and ins.operands[0].imm in (0x132a78, 0x132c64):
        print(f"  0x{ins.address:08x} -> 0x{ins.operands[0].imm:x}")
