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

# 打印所有 ADRP 目标页落在 0x28000-0x36000 (字符串区) 的指令
want_pages = set()
for p in range(0x28000, 0x36000, 0x1000):
    want_pages.add(p)

for insn in md.disasm(code, TEXT_VA):
    if insn.mnemonic == 'adrp':
        op = insn.operands[1]
        page = (insn.address & ~0xfff) + op.imm
        if page in want_pages:
            print("0x%x: adrp -> page 0x%x" % (insn.address, page))
