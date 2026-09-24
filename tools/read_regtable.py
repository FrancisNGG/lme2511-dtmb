so = '/tmp/android-extract/lib/arm64-v8a/reference_client.so'
data = open(so,'rb').read()

# 寄存器表 @0x3fc54, 28 对 [reg, value] (x22 从 0 到 54 步进 2)
# 但注意: 循环是 add x8, x23, x22, 然后 ldrb w1,[x8], ldrb w2,[x8+1]
# 而 x23 = adr #0x3fc54, 但 adr 是 PC-relative, 需要算绝对地址
# 0x118f9c: adr x23, #0x3fc54  -> 实际地址需要知道 adr 的语义
# adr 的目标 = PC + imm, 这里 imm = 0x3fc54, 但这是编码后的值

# 用 capstone 精确解析 adr 目标
from capstone import *
from capstone.arm64 import *
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

insn = list(md.disasm(data[0x118f9c:0x118fa0], 0x118f9c))[0]
print(f"adr: {insn.mnemonic} {insn.op_str}, 目标 = 0x{insn.operands[1].imm:x}")

table_addr = insn.operands[1].imm
print(f"\n=== 寄存器表 @0x{table_addr:x} (28 对) ===")
for i in range(28):
    off = table_addr + i*2
    reg = data[off]
    val = data[off+1]
    print(f"[{i:2d}] reg 0x{reg:02x} = 0x{val:02x}")
