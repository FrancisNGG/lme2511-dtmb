#!/usr/bin/env python3
# 找 lock_config(0x1384d0) 和 demod_resync(0x119b74) 的调用点, 重建锁定流程顺序
from capstone import *
from capstone.arm64 import *

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
TEXT_VA = 0xb6860
TEXT_SIZE = 0x11c700
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

print("=== bl 0x1384d0 (lock_config) 的直接调用点 ===")
for ins in md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA):
    if ins.mnemonic == 'bl' and ins.operands[0].imm == 0x1384d0:
        print(f"  0x{ins.address:08x}")

print("\n=== bl 0x119b74 (demod_resync) 的直接调用点 ===")
for ins in md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA):
    if ins.mnemonic == 'bl' and ins.operands[0].imm == 0x119b74:
        print(f"  0x{ins.address:08x}")

print("\n=== bl 0x119378 (recapture) 的调用点 ===")
for ins in md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA):
    if ins.mnemonic == 'bl' and ins.operands[0].imm == 0x119378:
        print(f"  0x{ins.address:08x}")

print("\n=== bl 0x119090 (carrier_config) 的调用点 ===")
for ins in md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA):
    if ins.mnemonic == 'bl' and ins.operands[0].imm == 0x119090:
        print(f"  0x{ins.address:08x}")

print("\n=== bl 0x119008 的调用点 (写 0x38=0x51 的? ) ===")
for ins in md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA):
    if ins.mnemonic == 'bl' and ins.operands[0].imm == 0x119008:
        print(f"  0x{ins.address:08x}")
