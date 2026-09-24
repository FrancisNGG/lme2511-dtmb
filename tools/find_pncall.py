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

# 搜索 bl 到 0x139164
calls = []
for insn in md.disasm(code, TEXT_VA):
    if insn.mnemonic == 'bl' and insn.operands[0].imm == 0x139164:
        calls.append(insn.address)

print("调用 0x139164 的地方:", [hex(x) for x in calls])

# 反汇编每个调用点前后
for c in calls:
    print("\n=== 调用点 0x%x 前后 ===" % c)
    code2 = data[c-0x40:c+0x20]
    for insn in md.disasm(code2, c-0x40):
        print("0x%x: %-9s %s" % (insn.address, insn.mnemonic, insn.op_str))
