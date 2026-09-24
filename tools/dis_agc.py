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
        comment = ""
        if insn.mnemonic.startswith('b') or insn.mnemonic in ('bl','cbz','cbnz','tbz','tbnz','b.eq','b.ne'):
            if len(insn.operands) > 0 and insn.operands[-1].type == ARM64_OP_IMM:
                t = insn.operands[-1].imm
                tag = ""
                if t == 0x119b74: tag = " <== demod_resync"
                elif t == 0x119090: tag = " <== carrier_config"
                elif t == 0x119378: tag = " <== recapture"
                elif t == 0x118f2c: tag = " <== FUN_118f2c"
                comment = f"  ; -> 0x{t:x}{tag}"
        print(f"0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str:30s}{comment}")

# 0x119008 所在函数 (0x38 写), 反汇编 0x118f00-0x119100
disasm(0x118f00, 0x200, "函数 @0x118f00-0x119100 (含 0x38 写 @0x119008)")
