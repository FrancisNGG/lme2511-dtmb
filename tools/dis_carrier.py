from capstone import *
from capstone.arm64 import *

so = '/tmp/android-extract/lib/arm64-v8a/reference_client.so'
data = open(so,'rb').read()

def disasm(va, nbytes, label):
    code = data[va:va+nbytes]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    print("=== %s @ 0x%x ===" % (label, va))
    for insn in md.disasm(code, va):
        print("0x%x: %-9s %s" % (insn.address, insn.mnemonic, insn.op_str))
    print()

# carrier 轮询 0x139790
disasm(0x139790, 0xc0, "carrier 轮询 0x139790")

# 搜索调用 0x1391a0 的地方
TEXT_VA = 0xb6860
TEXT_OFF = 0xb6860
TEXT_SIZE = 0x11c700
code = data[TEXT_OFF:TEXT_OFF+TEXT_SIZE]
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
print("=== 调用 0x1391a0 的地方 ===")
for insn in md.disasm(code, TEXT_VA):
    if insn.mnemonic == 'bl' and insn.operands[0].imm == 0x1391a0:
        print("0x%x: bl -> 0x1391a0" % insn.address)
