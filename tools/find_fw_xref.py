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

targets = {0x42b25: 'FW1_0x42B25', 0x56933: 'FW2_0x56933'}

hits = []
for insn in md.disasm(code, TEXT_VA):
    if insn.mnemonic == 'adrp':
        op = insn.operands[1]
        page = (insn.address & ~0xfff) + (op.imm << 12)
        for tgt, name in targets.items():
            if page == (tgt & ~0xfff):
                hits.append((insn.address, name, page, insn.mnemonic + ' ' + insn.op_str))
    elif insn.mnemonic == 'ldr' and insn.operands[1].type == ARM64_OP_MEM:
        mem = insn.operands[1].mem
        if mem.base == 0:
            lit_addr = insn.address + mem.disp
            for tgt, name in targets.items():
                if abs(lit_addr - tgt) < 0x1000:
                    hits.append((insn.address, name, lit_addr, insn.mnemonic + ' ' + insn.op_str))

print("total hits:", len(hits))
for h in hits:
    print("  0x%x  -> %s  (page/addr 0x%x)  %s" % h)
