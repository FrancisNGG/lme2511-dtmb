#!/usr/bin/env python3
# 逆向 0x1cc87c 完整逻辑, 理解 w1=0xc0/w3=1 读的含义
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
            names = {0x1d4090:'?', 0x1cad6c:'?', 0x1d3fe0:'alloc', 0x1d3210:'memcpy',
                     0x1d3900:'?', 0x1d3940:'nanosleep', 0x1cc87c:'SELF'}
            if tgt in names: note = "  ; <<< " + names[tgt]
        if ins.mnemonic == 'ret': note = "  ; <<<< RET"
        if ins.mnemonic in ('cbz','cbnz','tbz','tbnz'): note = f"  ; -> 0x{ins.operands[1].imm:x}"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x1cc980 ~ 0x1ccb40 ##########")
dis_range(0x1cc980, 0x1ccb40)
