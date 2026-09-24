#!/usr/bin/env python3
# Disassemble a function range from reference_client.so (VA == file offset)
import sys
from capstone import *
from capstone.arm64 import *

SO = "/tmp/android-extract/lib/arm64-v8a/reference_client.so"
with open(SO, "rb") as f:
    so = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

def disasm(start, end, label="", limit=100000):
    print(f"\n===== {label} @0x{start:x} .. 0x{end:x} =====")
    code = so[start:end]
    n = 0
    for insn in md.disasm(code, start):
        # print instruction with detail
        ops = insn.op_str
        comment = ""
        # decode branch target for B/BL
        if insn.mnemonic in ("b", "bl", "b.eq", "b.ne", "b.lt", "b.gt", "b.le", "b.ge", "cbz", "cbnz", "tbz", "tbnz"):
            for op in insn.operands:
                if op.type == ARM64_OP_IMM:
                    comment = f"; -> 0x{op.imm:x}"
        print(f"0x{insn.address:x}: {insn.mnemonic:8s} {ops:28s} {comment}")
        n += 1
        if n >= limit:
            print(f"... [truncated at {limit}]")
            break

if __name__ == "__main__":
    start = int(sys.argv[1], 16)
    end = int(sys.argv[2], 16)
    label = sys.argv[3] if len(sys.argv) > 3 else ""
    disasm(start, end, label)
