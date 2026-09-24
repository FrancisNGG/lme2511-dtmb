#!/usr/bin/env python3
# 逆向 0x11cdc8 (app ROM 读函数), 看读哪些 ROM 地址 + PD_TH 来源
from capstone import *
from capstone.arm64 import *

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

def dis_range(va, end):
    for ins in md.disasm(so[va:end], va):
        note = ""
        if ins.mnemonic in ('mov','movz','movk') and ins.operands[-1].type == ARM64_OP_IMM:
            note = f"  ; imm=0x{ins.operands[-1].imm:x}"
        if ins.mnemonic == 'bl':
            tgt = ins.operands[0].imm
            if tgt in (0x11cdc8,0x11887c,0x118e08,0x1cc87c,0x1256d8,0x125e80,0x1354c4): note = f"  ; bl 0x{tgt:x}"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x11cdc8 ~ 0x11cf80 ##########")
dis_range(0x11cdc8, 0x11cf80)
