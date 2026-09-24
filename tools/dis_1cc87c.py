#!/usr/bin/env python3
# 逆向 0x1cc87c - USB 控制传输写函数，理解 w1=0x40(写demod)/0xc0(读tuner) 的含义
from capstone import *
from capstone.arm64 import *

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

def dis_range(va, end):
    for ins in md.disasm(so[va:end], va):
        note = ""
        if ins.mnemonic in ('adr','adrp'):
            note = "  ; str?"
        if ins.mnemonic == 'ret': note = "  ; <<<< RET"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x1cc87c ~ 0x1cc960 ##########")
dis_range(0x1cc87c, 0x1cc980)
