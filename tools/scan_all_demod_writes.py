import sys
sys.path.insert(0, '/tmp/revenv/lib/python3.11/site-packages')
from capstone import *
from capstone.arm64 import *
so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

TEXT_START = 0xb6860
TEXT_END   = 0x1d2f60

insns = list(md.disasm(so[TEXT_START:TEXT_END], TEXT_START))

calls = []
for i, ins in enumerate(insns):
    if ins.mnemonic == 'bl' and ins.operands[0].imm == 0x11887c:
        # 回溯 10 条找 w1/w2 立即数
        reg = None; val = None
        for j in range(i-1, max(i-11, -1), -1):
            p = insns[j]
            if p.mnemonic == 'mov' and len(p.operands) == 2:
                dst, src = p.operands[0].reg, p.operands[1]
                if dst == ARM64_REG_W1 and src.type == ARM64_OP_IMM:
                    reg = src.imm
                elif dst == ARM64_REG_W2 and src.type == ARM64_OP_IMM:
                    val = src.imm
        calls.append((ins.address, reg, val))

# 分组: 找到立即数的和没找到的
print("=== 找到 reg/val 的 demod 写 ===")
seen = {}
for addr, reg, val in calls:
    if reg is not None and val is not None:
        key = (reg, val)
        if key not in seen:
            seen[key] = addr
for (reg, val), addr in sorted(seen.items()):
    print(f"  reg 0x{reg:02x} = 0x{val:02x}   (0x{addr:x})")

print(f"\n=== 未找到立即数的调用点 (w1/w2 是动态值) ===")
dyn = [a for a, r, v in calls if r is None or v is None]
for a in sorted(set(dyn)):
    print(f"  0x{a:x}")
print(f"\n总调用点: {len(calls)}, 静态 reg/val: {len(seen)}, 动态: {len(set(dyn))}")
