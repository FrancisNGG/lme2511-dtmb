from capstone import *
from capstone.arm64 import *

so = '/tmp/android-extract/lib/arm64-v8a/reference_client.so'
data = open(so,'rb').read()

text_va = 0xb6860
text_size = 0x11c700
code = data[text_va:text_va+text_size]
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# 找写 reg 0x3c/0x3d/0x3e/0x3f 的地方 (movz w1, #0x3x 后跟 bl 0x11887c/0x118e08)
insns = list(md.disasm(code, text_va))
for i, insn in enumerate(insns):
    if insn.mnemonic == 'movz' and insn.operands[0].type == ARM64_OP_REG:
        reg = insn.operands[0].reg
        imm = insn.operands[1].imm
        if reg == ARM64_REG_W1 and 0x38 <= imm <= 0x45:
            # 看后面 5 条指令是否有 bl 0x11887c 或 0x118e08
            for j in range(i, min(i+6, len(insns))):
                if insns[j].mnemonic == 'bl' and insns[j].operands[0].type == ARM64_OP_IMM:
                    t = insns[j].operands[0].imm
                    if t in (0x11887c, 0x118e08):
                        print(f"0x{insn.address:x}: movz w1, #0x{imm:x} -> bl 0x{t:x} (写 reg 0x{imm:x})")
                        break
