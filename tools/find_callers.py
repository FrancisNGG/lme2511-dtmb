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

# 搜索 demod_resync(0x119b74), 重捕获循环(0x119378), lock_config(0x1384d0) 的调用者
targets = {0x119b74: 'demod_resync', 0x119378: '重捕获循环', 0x1384d0: 'lock_config'}

for insn in md.disasm(code, TEXT_VA):
    if insn.mnemonic == 'bl':
        tgt = insn.operands[0].imm
        if tgt in targets:
            print("0x%x: bl -> 0x%x (%s)" % (insn.address, tgt, targets[tgt]))
