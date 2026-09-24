#!/usr/bin/env python3
# 逆向 0x118f2c (demod_full_init) 完整内容，重点 0x25 脉冲
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
            names = {0x11887c:'write_reg', 0x118e08:'rmw_reg', 0x119090:'carrier_config',
                     0x119008:'?0x119008', 0x1d3940:'nanosleep?', 0x118360:'log'}
            if tgt in names: note = "  ; <<< " + names[tgt]
        if ins.mnemonic == 'ret': note = "  ; <<<< RET"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x118f2c ~ 0x119090 (demod_full_init) ##########")
dis_range(0x118f2c, 0x119090)
