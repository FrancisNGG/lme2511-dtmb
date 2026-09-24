#!/usr/bin/env python3
# Find callers (xrefs) of given targets by scanning .text for BL/B/ADR/ADRP references
import sys
from capstone import *
from capstone.arm64 import *

SO = "/tmp/android-extract/lib/arm64-v8a/reference_client.so"
with open(SO, "rb") as f:
    so = f.read()

TEXT_START = 0xb6860
TEXT_END = TEXT_START + 0x11c700

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

targets = set(int(a, 16) for a in sys.argv[1:])

# scan text for direct branches and adrp/add pairs
code = so[TEXT_START:TEXT_END]
hits = {}
for insn in md.disasm(code, TEXT_START):
    tgt = None
    if insn.mnemonic in ("bl", "b", "b.eq", "b.ne", "b.lt", "b.gt", "b.le", "b.ge",
                         "b.hi", "b.ls", "b.cc", "b.cs", "b.mi", "b.pl", "b.vs", "b.vc",
                         "cbz", "cbnz", "tbz", "tbnz"):
        for op in insn.operands:
            if op.type == ARM64_OP_IMM:
                tgt = op.imm
    if tgt in targets:
        hits.setdefault(tgt, []).append((insn.address, insn.mnemonic, insn.op_str))

for tgt in sorted(targets):
    print(f"--- xrefs to 0x{tgt:x} ---")
    if tgt not in hits:
        print("  (none via direct branch)")
    else:
        for addr, mn, ops in hits[tgt]:
            print(f"  0x{addr:x}: {mn} {ops}")
    print()
