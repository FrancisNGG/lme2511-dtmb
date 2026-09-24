#!/usr/bin/env python3
# 找 vtable 0xc270 的引用 (谁通过它调 demod_resync)
from capstone import *
from capstone.arm64 import *

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
TEXT_VA = 0xb6860
TEXT_SIZE = 0x11c700
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

insns = list(md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA))

# vtable 0xc270 在页 0xc000, offset 0x270
page = 0xc000
print("=== adrp 0xc000 页 + add 0x270/0x298 (vtable 引用) ===")
for i, ins in enumerate(insns):
    if ins.mnemonic == 'adrp' and ins.operands[1].imm == page:
        reg = ins.operands[0].reg
        for j in range(i+1, min(i+5, len(insns))):
            jin = insns[j]
            if jin.mnemonic == 'add' and jin.operands[0].reg == reg:
                if jin.operands[2].type == ARM64_OP_IMM:
                    off = jin.operands[2].imm
                    if off in (0x270, 0x280, 0x298, 0x2b0):
                        print(f"  0x{ins.address:08x}: adrp+add -> 0x{page+off:x} (vtable {'+'+hex(off)})")
                        # 打印上下文 (调用点前后)
                        for k in range(max(0,i-2), min(len(insns), j+6)):
                            kin = insns[k]
                            tag = "  <<<<" if k == ins.address else "     "
                            print(f"       {kin.address:08x}: {kin.mnemonic} {kin.op_str}{tag}")
