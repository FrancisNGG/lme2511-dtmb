import sys
sys.path.insert(0, '/tmp/revenv/lib/python3.11/site-packages')
from capstone import *
from capstone.arm64 import *
so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

TEXT_START = 0xb6860
TEXT_END   = 0x1d2f60

# 找所有 mov w1/w2 = #0x3e 或 #0x3f 或 #0x28 的立即数 (可能是 demod 写 reg=0x3E 或 val=0x28)
insns = list(md.disasm(so[TEXT_START:TEXT_END], TEXT_START))
targets = {0x3e: 'reg 0x3E(AGC低)', 0x3f: 'reg 0x3F(AGC高)', 0x28: 'val 0x28'}

print("=== mov w1/w2 含 0x3e/0x3f/0x28 的位置 ===")
for i, ins in enumerate(insns):
    if ins.mnemonic == 'mov' and len(ins.operands) == 2:
        dst = ins.operands[0].reg
        src = ins.operands[1]
        if dst in (ARM64_REG_W1, ARM64_REG_W2) and src.type == ARM64_OP_IMM and src.imm in targets:
            # 看后面 3 条内是否有 bl (写调用)
            ctx = ''
            for j in range(i+1, min(i+4, len(insns))):
                if insns[j].mnemonic == 'bl':
                    ctx = f'  -> bl 0x{insns[j].operands[0].imm:x}'
                    break
            print(f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}  [{targets[src.imm]}]{ctx}")
