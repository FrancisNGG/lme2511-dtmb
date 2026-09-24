from capstone import *
from capstone.arm64 import *

so = '/tmp/android-extract/lib/arm64-v8a/reference_client.so'
data = open(so,'rb').read()
TEXT_VA = 0xb6860
TEXT_OFF = 0xb6860
TEXT_SIZE = 0x11c700
code = data[TEXT_OFF:TEXT_OFF+TEXT_SIZE]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

strs = {
    0x33658: "raw split firmware unavailable",
    0x358b4: "upload raw split variant rom fw",
    0x2ff5d: "firmware size not aligned to chunk",
    0x2a0b4: "Lme2510Driver::open",
    0x33f51: "LME2510C cold boot uploaded",
    0x2b2b4: "raw split requires cold bootloader",
}

insns = list(md.disasm(code, TEXT_VA))
for i, insn in enumerate(insns):
    if insn.mnemonic == 'adrp':
        # op.imm 已是目标页地址
        page = insn.operands[1].imm
        add_off = 0
        if i+1 < len(insns) and insns[i+1].mnemonic == 'add':
            a = insns[i+1]
            if a.operands[2].type == ARM64_OP_IMM:
                add_off = a.operands[2].imm
        full = page + add_off
        for saddr, name in strs.items():
            if full == saddr:
                print("HIT STR 0x%x: %s @ 0x%x  [%s %s]" % (saddr, name, insn.address, insn.mnemonic, insn.op_str))
    elif insn.mnemonic == 'adr':
        # adr: op.imm 是偏移
        full = insn.address + insn.operands[1].imm
        for saddr, name in strs.items():
            if full == saddr:
                print("HIT STR(adr) 0x%x: %s @ 0x%x" % (saddr, name, insn.address))
print("done")
