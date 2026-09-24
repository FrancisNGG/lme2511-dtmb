#!/usr/bin/env python3
# 找 demod_resync(0x119b74) 的引用 (间接调用), 重建锁定流程顺序
from capstone import *
from capstone.arm64 import *

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
TEXT_VA = 0xb6860
TEXT_SIZE = 0x11c700
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# 找 adrp 指向 0x119000 页, 后面 add 0xb74 (demod_resync)
target_page = 0x119000
print("=== adrp 0x119000 页 (demod_resync 所在页) 的引用 ===")
insns = list(md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA))
for i, ins in enumerate(insns):
    if ins.mnemonic == 'adrp' and ins.operands[1].imm == target_page:
        # 看后面是否 add 0xb74
        reg = ins.operands[0].reg
        for j in range(i+1, min(i+4, len(insns))):
            jin = insns[j]
            if jin.mnemonic == 'add' and jin.operands[0].reg == reg and jin.operands[1].reg == reg:
                if jin.operands[2].type == ARM64_OP_IMM and jin.operands[2].imm == 0xb74:
                    print(f"  0x{ins.address:08x}: adrp {ins.op_str}  + add 0xb74 (demod_resync 地址)")
                elif jin.operands[2].type == ARM64_OP_IMM:
                    print(f"  0x{ins.address:08x}: adrp {ins.op_str}  + add 0x{jin.operands[2].imm:x}")
