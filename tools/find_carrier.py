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

# 搜索 movz 立即数为 0x4b(75) / 0xa4(164) / 0x04 / 0x37 的地方
targets = {0x4b: 'REG_4B carrier', 0xa4: 'REG_A4 status', 0x04: 'REG_04 PN', 0x37: 'REG_37'}

hits = []
for insn in md.disasm(code, TEXT_VA):
    if insn.mnemonic in ('movz', 'mov'):
        for op in insn.operands:
            if op.type == ARM64_OP_IMM and op.imm in targets:
                hits.append((insn.address, op.imm, insn.mnemonic + ' ' + insn.op_str))

for h in hits:
    print("0x%x: imm=0x%x (%s)  %s" % (h[0], h[1], targets[h[1]], h[2]))
print("total:", len(hits))
