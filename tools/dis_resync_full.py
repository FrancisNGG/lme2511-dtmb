from capstone import *
from capstone.arm64 import *

so = '/tmp/android-extract/lib/arm64-v8a/reference_client.so'
data = open(so,'rb').read()

def disasm(va, nbytes, label):
    print(f"\n=== {label} @ 0x{va:x} ({nbytes} bytes) ===")
    code = data[va:va+nbytes]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    for insn in md.disasm(code, va):
        # annotate branch targets
        comment = ""
        if insn.mnemonic.startswith('b') or insn.mnemonic in ('bl','cbz','cbnz','tbz','tbnz','b.eq','b.ne'):
            if len(insn.operands) > 0 and insn.operands[-1].type == ARM64_OP_IMM:
                comment = f"  ; -> 0x{insn.operands[-1].imm:x}"
        print(f"0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str:30s}{comment}")

# demod_resync @0x119b74 完整 (到 recapture 调用 bl 0x119378 附近)
disasm(0x119b74, 0x500, "demod_resync @0x119b74")
