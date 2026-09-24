#!/usr/bin/env python3
# 逆向 0x134328 / 0x1346a0 附近, 理解调用 0x1323f0(写0x48=0) 的时机
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
            names = {0x1323f0:'wr_alt_func(0x48=0)', 0x118f2c:'demod_full_init', 0x119090:'carrier_config',
                     0x119b74:'demod_resync', 0x1384d0:'lock_config', 0x119378:'recapture',
                     0x132a78:'sub_132a78', 0x132c64:'sub_132c64'}
            if tgt in names: note = "  ; <<< " + names[tgt]
        if ins.mnemonic == 'ret': note = "  ; <<<< RET"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x134200 ~ 0x134800 ##########")
dis_range(0x134200, 0x134800)
