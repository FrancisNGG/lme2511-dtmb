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

# 统计 adrp 的 imm 符号，以及负 imm 的目标页
neg = 0
pos = 0
examples = []
for insn in md.disasm(code, TEXT_VA):
    if insn.mnemonic == 'adrp':
        op = insn.operands[1]
        if op.imm < 0:
            neg += 1
            if len(examples) < 15:
                page = (insn.address & ~0xfff) + op.imm
                examples.append((insn.address, op.imm, page, insn.op_str))
        else:
            pos += 1

print("adrp 负 imm: %d, 正 imm: %d" % (neg, pos))
print("负 imm 示例 (addr, imm, page, op_str):")
for e in examples:
    print("  0x%x imm=0x%x page=0x%x  %s" % e)
