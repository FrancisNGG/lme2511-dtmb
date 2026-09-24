from capstone import *
from capstone.arm64 import *

so = '/tmp/android-extract/lib/arm64-v8a/reference_client.so'
data = open(so,'rb').read()

# 搜索整个 .text 里的 bl #0x119b74 (demod_resync) 和 bl #0x1384d0 (lock_config)
text_va = 0xb6860
text_size = 0x11c700
code = data[text_va:text_va+text_size]
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

print("=== bl #0x119b74 (demod_resync 调用点) ===")
for insn in md.disasm(code, text_va):
    if insn.mnemonic == 'bl' and insn.operands[0].type == ARM64_OP_IMM:
        if insn.operands[0].imm == 0x119b74:
            print(f"0x{insn.address:x}: bl 0x119b74")

print("\n=== bl #0x1384d0 (lock_config 调用点) ===")
for insn in md.disasm(code, text_va):
    if insn.mnemonic == 'bl' and insn.operands[0].type == ARM64_OP_IMM:
        if insn.operands[0].imm == 0x1384d0:
            print(f"0x{insn.address:x}: bl 0x1384d0")

print("\n=== 函数指针引用 0x119b74 (demod_resync) 在 .data.rel.ro/.data ===")
import struct
target = struct.pack('<Q', 0x119b74)
# .data.rel.ro 和 .data 大致范围 (需先查 readelf, 这里用宽范围扫描)
for off in range(0x1d0000, len(data)-8):
    if data[off:off+8] == target:
        print(f"file offset 0x{off:x} (VA=0x{off:x}) -> 0x119b74")
