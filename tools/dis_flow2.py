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
                if t == 0x119b74: tag = "  <== demod_resync"
                elif t == 0x1384d0: tag = "  <== lock_config"
                elif t == 0x119378: tag = "  <== recapture"
                elif t == 0x119090: tag = "  <== carrier_config"
                elif t == 0x13ad24: tag = "  <== freq_set"
                elif t == 0x139988: tag = "  <== wait_lock"
                elif t == 0x1391a0: tag = "  <== lock_poll"
                comment = f"  ; -> 0x{t:x}{tag}"
        print(f"0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str:30s}{comment}")

# 0x136d9c 所在函数 (0x136e58 调用 lock_config 的地方) 完整
disasm(0x136d9c, 0x200, "函数@0x136d9c (含 lock_config 调用 @0x136e58)")
