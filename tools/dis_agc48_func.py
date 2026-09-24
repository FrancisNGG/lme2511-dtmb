#!/usr/bin/env python3
# 逆向 0x1325xx 函数完整上下文 (写 0x48=0), 找函数起点和用途
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
            names = {0x1354c4:'wr_1354c4', 0x13559c:'wr_13559c', 0x137910:'wr_137910',
                     0x11887c:'write_reg', 0x118e08:'rmw_reg', 0x119090:'carrier_config',
                     0x118f2c:'demod_full_init', 0x1384d0:'lock_config'}
            if tgt in names: note = "  ; <<< " + names[tgt]
        if ins.mnemonic == 'ret': note = "  ; <<<< RET"
        if ins.mnemonic == 'mov' and ins.operands[0].reg in (ARM64_REG_W1,ARM64_REG_W2,ARM64_REG_W3) and ins.operands[1].type == ARM64_OP_IMM:
            note += f"  ; w{ins.operands[0].reg-ARM64_REG_W0}=0x{ins.operands[1].imm:02x}"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x132380 ~ 0x132700 (写 0x48=0 的函数) ##########")
dis_range(0x132380, 0x132700)
