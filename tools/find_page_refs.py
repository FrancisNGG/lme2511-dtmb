#!/usr/bin/env python3
# Find ADRP+ADD/LDR references to a given 4KB page and any nearby offset
import sys
from capstone import *
from capstone.arm64 import *

SO = "/tmp/android-extract/lib/arm64-v8a/reference_client.so"
so = open(SO, "rb").read()
TEXT_START = 0xb6860
TEXT_END = TEXT_START + 0x11c700

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
code = so[TEXT_START:TEXT_END]
insns = list(md.disasm(code, TEXT_START))

# targets: page + offset ranges we care about
# table base 0x1d7ab0 -> page 0x1d7000, offsets 0xa90..0xaf0
pages = {int(a,16) for a in sys.argv[1:]}

def page_of(insn):
    for op in insn.operands:
        if op.type == ARM64_OP_IMM:
            return op.imm
    return None

for i, insn in enumerate(insns):
    if insn.mnemonic != "adrp":
        continue
    pg = page_of(insn)
    if pg is None or pg not in pages:
        continue
    # print the adrp + next 2 insns
    for j in range(i, min(i+3, len(insns))):
        print(f"0x{insns[j].address:x}: {insns[j].mnemonic:8s} {insns[j].op_str}")
    print("   ---")
