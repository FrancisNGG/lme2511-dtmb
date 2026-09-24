#!/usr/bin/env python3
# 逆向 app init @0x1226F8 完整序列, 找所有 reg 写 (特别是 reg 0x00)
from capstone import *
from capstone.arm64 import *

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

def dis_range(va, end):
    for ins in md.disasm(so[va:end], va):
        note = ""
        if ins.mnemonic == 'bl':
            tgt = ins.operands[0].imm
            names = {0x11887c:'write_reg', 0x118e08:'rmw_reg', 0x1d3940:'nanosleep',
                     0x118360:'log', 0x1cc87c:'usb_xfer', 0x118c2c:'soft_reset'}
            if tgt in names: note = "  ; <<< " + names[tgt]
        if ins.mnemonic == 'ret': note = "  ; <<<< RET"
        # 高亮 mov w1/w2 寄存器写
        if ins.mnemonic == 'mov' and ins.operands[0].reg == ARM64_REG_W1 and ins.operands[1].type == ARM64_OP_IMM:
            note += f"  ; reg=0x{ins.operands[1].imm:02x}"
        if ins.mnemonic == 'mov' and ins.operands[0].reg == ARM64_REG_W2 and ins.operands[1].type == ARM64_OP_IMM:
            note += f"  ; val=0x{ins.operands[1].imm:02x}"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x1226F8 ~ 0x122900 (init) ##########")
dis_range(0x1226F8, 0x122900)
