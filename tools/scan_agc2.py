#!/usr/bin/env python3
# 扩展扫描 app 里所有写 reg 0x38-0x4f 的地方 (含直接 USB 0x1cc87c 数据缓冲区的 reg 字节)
from capstone import *
from capstone.arm64 import *

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
TEXT_VA = 0xb6860
TEXT_SIZE = 0x11c700
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

insns = list(md.disasm(so[TEXT_VA:TEXT_VA+TEXT_SIZE], TEXT_VA))

def backscan_w1(insns, idx):
    for i in range(idx-1, max(idx-8,0), -1):
        ins = insns[i]
        if ins.mnemonic == 'mov' and ins.operands[0].reg == ARM64_REG_W1 and ins.operands[1].type == ARM64_OP_IMM:
            return ins.operands[1].imm
    return None

def backscan_w2(insns, idx):
    for i in range(idx-1, max(idx-8,0), -1):
        ins = insns[i]
        if ins.mnemonic == 'mov' and ins.operands[0].reg == ARM64_REG_W2 and ins.operands[1].type == ARM64_OP_IMM:
            return ins.operands[1].imm
    return None

# 1. write_reg(0x11887c) + rmw_reg(0x118e08) 写 reg 0x38-0x4f
print("=== write_reg/rmw_reg 写 reg 0x38-0x4f ===")
for idx, ins in enumerate(insns):
    if ins.mnemonic == 'bl' and ins.operands[0].imm in (0x11887c, 0x118e08):
        w1 = backscan_w1(insns, idx)
        if w1 is not None and 0x38 <= w1 <= 0x4f:
            fn = 'write' if ins.operands[0].imm == 0x11887c else 'rmw'
            w2 = backscan_w2(insns, idx)
            print(f"  0x{ins.address:08x}: {fn} reg 0x{w1:02x} = 0x{w2:02x}")

# 2. 直接 USB 0x1cc87c 写, 数据缓冲区 [sp+off] 的 reg 字节 (strb/strh 写入 0x38-0x4f)
print("\n=== 直接 USB 0x1cc87c 写 reg 0x38-0x4f (数据缓冲区的 reg 字节) ===")
for idx, ins in enumerate(insns):
    if ins.mnemonic == 'bl' and ins.operands[0].imm == 0x1cc87c:
        # 往前找 12 条指令, 看 strb/strh 写入的字节值
        for j in range(idx-1, max(idx-14,0), -1):
            jin = insns[j]
            if jin.mnemonic in ('strb','strh'):
                # 找写入的立即数 (mov wN, #imm 之前)
                src = jin.operands[1].reg
                for k in range(j-1, max(j-5,0), -1):
                    kin = insns[k]
                    if kin.mnemonic in ('mov','movz') and kin.operands[0].reg == src and kin.operands[1].type == ARM64_OP_IMM:
                        v = kin.operands[1].imm & 0xff
                        if 0x38 <= v <= 0x4f:
                            print(f"  0x{ins.address:08x}: USB写 reg 0x{v:02x} (来自 0x{kin.address:08x} {kin.op_str})")
                        break

# 3. 找 0x38/0x39/0x3a/0x3b/0x3c/0x3d/0x3e/0x3f 等所有 mov w1,#reg 后跟 bl (任何写函数)
print("\n=== 所有写函数(w1=0x38-0x4f) 的调用 ===")
for idx, ins in enumerate(insns):
    if ins.mnemonic == 'bl':
        w1 = backscan_w1(insns, idx)
        if w1 is not None and 0x38 <= w1 <= 0x4f:
            print(f"  0x{ins.address:08x}: bl 0x{ins.operands[0].imm:08x} reg 0x{w1:02x}")
