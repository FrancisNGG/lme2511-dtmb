#!/usr/bin/env python3
# Find ADRP+ADD/LDR references to the function-pointer table around 0xc268..0xc2d0
from capstone import *
from capstone.arm64 import *

SO = "/tmp/android-extract/lib/arm64-v8a/reference_client.so"
so = open(SO, "rb").read()
TEXT_START = 0xb6860
TEXT_END = TEXT_START + 0x11c700

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

code = so[TEXT_START:TEXT_END]
insns = list(md.disasm(code, TEXT_START))

def adrp_page(insn):
    for op in insn.operands:
        if op.type == ARM64_OP_IMM:
            # ADRP immediate is page offset; page = (addr & ~0xfff) but capstone gives page addr
            return op.imm
    return None

# We want references to addresses 0xc260..0xc2d0 -> page 0xc000
for i, insn in enumerate(insns):
    if insn.mnemonic != "adrp":
        continue
    page = adrp_page(insn)
    if page is None:
        continue
    if 0xc000 <= page <= 0xc000:  # page 0xc000
        # look ahead up to 3 insns for add/ldr with offset in [0x260, 0x2e0]
        for j in range(i+1, min(i+4, len(insns))):
            nxt = insns[j]
            if nxt.mnemonic in ("add", "ldr", "str"):
                off = None
                for op in nxt.operands:
                    if op.type == ARM64_OP_IMM:
                        off = op.imm
                if off is not None and 0x260 <= off <= 0x2e0:
                    print(f"0x{nxt.address:x}: {nxt.mnemonic} {nxt.op_str}  (page 0x{page:x}, off 0x{off:x} -> 0x{page+off:x})")
