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

disasm(0x118c2c, 0x90, "0x118c2c (重捕获循环里的关键函数)")
