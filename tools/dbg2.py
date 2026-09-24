from capstone import *
from capstone.arm64 import *

so = '/tmp/android-extract/lib/arm64-v8a/reference_client.so'
data = open(so,'rb').read()

# .text VA=offset
def disasm_range(va, nbytes):
    off = va  # VA=offset for .text
    code = data[off:off+nbytes]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    for insn in md.disasm(code, va):
        print("0x%x: %-8s %s" % (insn.address, insn.mnemonic, insn.op_str))
    print()

# 反汇编 .text 开头，看 adrp 的语义
disasm_range(0xb6860, 0x60)
