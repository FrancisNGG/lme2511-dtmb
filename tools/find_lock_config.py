#!/usr/bin/env python3
# 找引用 0x1388cc (09..0C=A1BC8632) 的函数 = lock_config, 以及相关
from capstone import *
from capstone.arm64 import *
import struct

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
TEXT_VA = 0xb6860
TEXT_SIZE = 0x11c700
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

target = 0x1388cc
# 1. adrp 引用 (目标页)
tgt_page = target & ~0xfff
tgt_off = target & 0xfff
print(f"目标 0x{target:x}, 页 0x{tgt_page:x}, 页内偏移 0x{tgt_off:x}")

print("\n=== ADRP 引用该页 ===")
for ins in md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA):
    if ins.mnemonic == 'adrp' and ins.operands[1].imm == tgt_page:
        print(f"  0x{ins.address:08x}: adrp {ins.op_str}")

# 2. 直接找 32 位值 0x3286bca1 (LE 的 A1BC8632) 作为 literal
pat = struct.pack('<I', 0x3286bca1)
print("\n=== literal 0x3286bca1 出现位置 ===")
import re
for m in re.finditer(re.escape(pat), so):
    print(f"  文件偏移 0x{m.start():x} (VA 0x{m.start():x})")

# 3. 找 0x86bca1 或 0xbca1 等部分 (可能 mov/movk 构造)
print("\n=== 找 w8 寄存器加载 0x3286bca1 附近的 mov/movk (构造该值) ===")
for ins in md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA):
    if ins.mnemonic in ('mov','movz','movk') and ins.operands[-1].type == ARM64_OP_IMM:
        v = ins.operands[-1].imm
        if v in (0xbca1, 0x86bc, 0x3286, 0xa1, 0xbc, 0x86, 0x32):
            print(f"  0x{ins.address:08x}: {ins.mnemonic} {ins.op_str}")
