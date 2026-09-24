#!/usr/bin/env python3
# 逆向 tuner set_params 的两个调用点 0x122fcc 和 0x123790
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
            names = {0x126cb8:'tuner_set_params', 0x119b74:'demod_resync', 0x1384d0:'lock_config',
                     0x118f2c:'demod_full_init', 0x119090:'carrier_config', 0x11887c:'write_reg'}
            if tgt in names: note = "  ; <<< " + names[tgt]
        if ins.mnemonic == 'ret': note = "  ; <<<< RET"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x122f80 ~ 0x123010 (tuner set_params 调用点1) ##########")
dis_range(0x122f80, 0x123010)
print("\n########## 0x123740 ~ 0x1237e0 (tuner set_params 调用点2) ##########")
dis_range(0x123740, 0x1237e0)
