from capstone import *
from capstone.arm64 import *

so = '/tmp/android-extract/lib/arm64-v8a/reference_client.so'
data = open(so,'rb').read()
TEXT_VA = 0xb6860
TEXT_OFF = 0xb6860
TEXT_SIZE = 0x11c700
code = data[TEXT_OFF:TEXT_OFF+TEXT_SIZE]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# 目标字符串/fw 地址的十六进制（小写，无前导0x）
targets = ['358b4','2ff5d','33658','2a0b4','33f51','2b2b4','42b05','568f3']

hits = 0
for insn in md.disasm(code, TEXT_VA):
    s = insn.op_str.lower()
    for t in targets:
        if t in s:
            print("0x%x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
            hits += 1
print("hits:", hits)
