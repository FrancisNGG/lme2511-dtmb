#!/usr/bin/env python3
# 逆向 0x1354c4 写函数, 确认写的 I2C 地址 (demod 0x19 vs alt 0x1b)
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
            names = {0x1cc87c:'usb_xfer', 0x13559c:'wr_13559c', 0x129110:'wr_129110',
                     0x135684:'wr_135684'}
            if tgt in names: note = "  ; <<< " + names[tgt]
        if ins.mnemonic == 'ret': note = "  ; <<<< RET"
        if ins.mnemonic == 'mov' and ins.operands[0].reg in (ARM64_REG_W1,ARM64_REG_W2,ARM64_REG_W3) and ins.operands[1].type == ARM64_OP_IMM:
            note += f"  ; w{ins.operands[0].reg-ARM64_REG_W0}=0x{ins.operands[1].imm:02x}"
        if ins.mnemonic in ('movz','movk') and ins.operands[-1].type == ARM64_OP_IMM:
            note += f"  ; imm=0x{ins.operands[-1].imm:x}"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x1354c4 ~ 0x13559c ##########")
dis_range(0x1354c4, 0x13559c)
