#!/usr/bin/env python3
# 扫描所有 blr(间接调用), 找 demod_resync(0x119b74)/lock_config(0x1384d0) 的调用点
from capstone import *
from capstone.arm64 import *

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
TEXT_VA = 0xb6860
TEXT_SIZE = 0x11c700
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

insns = list(md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA))

targets = {0x119b74:'demod_resync', 0x1384d0:'lock_config', 0x119378:'recapture', 0x119090:'carrier_config'}

# 对每个 blr, 往前找 x 寄存器从哪加载 (adrp+add 或 ldr)
for i, ins in enumerate(insns):
    if ins.mnemonic == 'blr':
        breg = ins.operands[0].reg
        # 往前 12 条找加载 breg 的 adrp/add
        for j in range(i-1, max(i-13,0), -1):
            jin = insns[j]
            if jin.mnemonic == 'adrp' and jin.operands[0].reg == breg:
                page = jin.operands[1].imm
                # 找后续 add 到 breg
                for k in range(j+1, min(j+5, i)):
                    kin = insns[k]
                    if kin.mnemonic == 'add' and kin.operands[0].reg == breg and kin.operands[2].type == ARM64_OP_IMM:
                        full = page + kin.operands[2].imm
                        if full in targets:
                            print(f"  0x{ins.address:08x}: blr {ins.op_str}  -> {targets[full]} (0x{full:x})")
                        break
                break
