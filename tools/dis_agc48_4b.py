#!/usr/bin/env python3
# 逆向 0x132604(写reg 0x48) 和 0x12f1e4(写reg 0x4b) 上下文
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
            names = {0x1354c4:'write_fn_1354c4', 0x137910:'write_fn_137910', 0x11887c:'write_reg',
                     0x118e08:'rmw_reg', 0x135684:'write_fn_135684', 0x1cc87c:'usb_xfer'}
            if tgt in names: note = "  ; <<< " + names[tgt]
        if ins.mnemonic == 'ret': note = "  ; <<<< RET"
        if ins.mnemonic == 'mov' and ins.operands[0].reg in (ARM64_REG_W1,ARM64_REG_W2,ARM64_REG_W3) and ins.operands[1].type == ARM64_OP_IMM:
            note += f"  ; w{ins.operands[0].reg-ARM64_REG_W0}=0x{ins.operands[1].imm:02x}"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x1325b0 ~ 0x132640 (写 reg 0x48) ##########")
dis_range(0x1325b0, 0x132640)
print("\n########## 0x12f1a0 ~ 0x12f220 (写 reg 0x4b) ##########")
dis_range(0x12f1a0, 0x12f220)
