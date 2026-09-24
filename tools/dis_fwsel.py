from capstone import *
from capstone.arm64 import *

so = '/tmp/android-extract/lib/arm64-v8a/reference_client.so'
data = open(so,'rb').read()

def disasm(va, nbytes):
    off = va  # .text VA=offset
    code = data[off:off+nbytes]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    for insn in md.disasm(code, va):
        print("0x%x: %-9s %s" % (insn.address, insn.mnemonic, insn.op_str))

# 反汇编 0x13fa00 - 0x13fc00（firmware 选择函数附近）
disasm(0x13fa00, 0x200)
