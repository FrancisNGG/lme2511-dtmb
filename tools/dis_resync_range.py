#!/usr/bin/env python3
# 逆向 0x119b74 ~ 0x11a100 完整范围，理清 demod_resync 结构 + 0x119f30 身份
from capstone import *
from capstone.arm64 import *

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

def dis_range(va, end):
    for ins in md.disasm(so[va:end], va):
        # 标注关键调用
        note = ""
        if ins.mnemonic == 'bl':
            tgt = ins.operands[0].imm
            names = {0x119378:'recapture', 0x119090:'carrier_config', 0x118f2c:'demod_full_init',
                     0x119b74:'demod_resync', 0x119008:'?0x119008', 0x118e08:'rmw_reg',
                     0x11887c:'write_reg'}
            if tgt in names: note = "  ; <<< " + names[tgt]
        if ins.mnemonic == 'ret': note = "  ; <<<<< RET"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x119b74 ~ 0x11a080 (demod_resync + 后续) ##########")
dis_range(0x119b74, 0x11a080)
