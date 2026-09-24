#!/usr/bin/env python3
# 逆向 0x127124 (chip ID 读函数), 确认读哪个 reg
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
            names = {0x1cc87c:'usb_xfer', 0x11887c:'write_reg', 0x118e08:'rmw_reg'}
            if tgt in names: note = "  ; <<< " + names[tgt]
        if ins.mnemonic == 'ret': note = "  ; <<<< RET"
        if ins.mnemonic == 'mov' and ins.operands[0].reg in (ARM64_REG_W1,ARM64_REG_W2,ARM64_REG_W3) and ins.operands[1].type == ARM64_OP_IMM:
            note += f"  ; w{ins.operands[0].reg-ARM64_REG_W0}=0x{ins.operands[1].imm:02x}"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x127124 ~ 0x127200 ##########")
dis_range(0x127124, 0x127200)
