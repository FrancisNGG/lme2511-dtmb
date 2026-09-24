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

# raw split 上传函数（0x120b44 引用字符串，往前找函数头）
disasm(0x120a80, 0x200, "raw split 上传")
