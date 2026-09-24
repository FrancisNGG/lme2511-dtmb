#!/usr/bin/env python3
# 逆向 0x11979c (vtable 里 demod_resync 前) 和 0x100afc (后)
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
            names = {0x119b74:'demod_resync', 0x119090:'carrier_config', 0x118f2c:'demod_full_init',
                     0x1384d0:'lock_config', 0x119378:'recapture', 0x11887c:'write_reg', 0x118e08:'rmw_reg'}
            if tgt in names: note = "  ; <<< " + names[tgt]
        if ins.mnemonic == 'ret': note = "  ; <<<< RET"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x11979c ~ 0x119800 ##########")
dis_range(0x11979c, 0x119800)
print("\n########## 0x100afc ~ 0x100b60 ##########")
dis_range(0x100afc, 0x100b60)
