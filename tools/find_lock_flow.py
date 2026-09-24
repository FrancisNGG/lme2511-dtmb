#!/usr/bin/env python3
# 逆向 app 完整锁定流程时序：找 lock_config 地址、demod_resync 调用点、recapture 调用点
from capstone import *
from capstone.arm64 import *

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
BASE = 0  # VA = file offset
TEXT_VA = 0xb6860
TEXT_SIZE = 0x11c700

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

def dis(va, n):
    code = so[va:va+n*4]
    return list(md.disasm(code, va))

# 1. 找引用 0x1388cc (09..0C = A1BC8632 的硬编码) 的函数 -> lock_config
import struct
def find_refs(target, start=TEXT_VA, end=TEXT_VA+TEXT_SIZE):
    """找 ADRP 指向 target 页 + ADD 引用的位置"""
    refs = []
    tgt_page = target & ~0xfff
    for ins in md.disasm(so[start:end], start):
        if ins.mnemonic == 'adrp':
            page = ins.operands[1].imm  # 目标页地址
            if page == tgt_page:
                # 看后面的 add/ldr 用这个 reg + offset 是否 = target
                refs.append((ins.address, ins.op_str))
    return refs

print("=== 引用 0x1388cc (lock_config 的 09..0C 参数) 的 ADRP ===")
for r in find_refs(0x1388cc):
    print(hex(r[0]), r[1])

# 2. 找 0x119b74 (demod_resync) 的调用点 - bl 直接调用
print("\n=== bl 0x119b74 (demod_resync) 的直接调用点 ===")
for ins in md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA):
    if ins.mnemonic == 'bl' and ins.operands[0].imm == 0x119b74:
        print(hex(ins.address))

# 3. 找 0x119378 (recapture) 的调用点
print("\n=== bl 0x119378 (recapture) 的调用点 ===")
for ins in md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA):
    if ins.mnemonic == 'bl' and ins.operands[0].imm == 0x119378:
        print(hex(ins.address))

# 4. 找 0x119090 (carrier_config) 的调用点
print("\n=== bl 0x119090 (carrier_config) 的调用点 ===")
for ins in md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA):
    if ins.mnemonic == 'bl' and ins.operands[0].imm == 0x119090:
        print(hex(ins.address))

# 5. 找 0x118f2c (demod_full_init) 的调用点
print("\n=== bl 0x118f2c (demod_full_init) 的调用点 ===")
for ins in md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA):
    if ins.mnemonic == 'bl' and ins.operands[0].imm == 0x118f2c:
        print(hex(ins.address))
