#!/usr/bin/env python3
# 逆向 0x136e58 附近 (频点设置→lock_config) 找 demod_resync 间接调用
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
            names = {0x1384d0:'lock_config', 0x119378:'recapture', 0x119090:'carrier_config',
                     0x118f2c:'demod_full_init', 0x119b74:'demod_resync'}
            if tgt in names: note = "  ; <<< " + names[tgt]
        if ins.mnemonic == 'blr': note = "  ; <<<< INDIRECT CALL (可能 demod_resync)"
        if ins.mnemonic == 'ret': note = "  ; <<<< RET"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x136c80 ~ 0x136f00 (频点设置函数) ##########")
dis_range(0x136c80, 0x136f00)
