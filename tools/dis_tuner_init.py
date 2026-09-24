#!/usr/bin/env python3
# 逆向 app tuner init (0x122900~0x122c58, chip==0x0e 分支), 找 reg 0x05/0x08/0x09 值
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
            names = {0x125e80:'write_fn_125e80', 0x125804:'write_fn_125804', 0x1256d8:'read_fn',
                     0x1264d0:'write_fn_1264d0', 0x127124:'parse_fn', 0x1d3940:'nanosleep'}
            if tgt in names: note = "  ; <<< " + names[tgt]
        if ins.mnemonic == 'ret': note = "  ; <<<< RET"
        if ins.mnemonic == 'mov' and ins.operands[0].reg in (ARM64_REG_W1,ARM64_REG_W2) and ins.operands[1].type == ARM64_OP_IMM:
            note += f"  ; w{ins.operands[0].reg-ARM64_REG_W0}=0x{ins.operands[1].imm:02x}"
        print(f"{ins.address:08x}: {ins.mnemonic}\t{ins.op_str}{note}")

print("########## 0x122900 ~ 0x122c58 ##########")
dis_range(0x122900, 0x122c58)
