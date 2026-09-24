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
    0x358b4: "upload raw split variant=%s rom=%zu fw=%zu",
    0x2ff5d: "firmware size not aligned to chunk",
    0x2a0b4: "Lme2510Driver::open",
    0x33f51: "LME2510C cold boot uploaded",
    0x2b2b4: "raw split requires cold bootloader",
}
fws = {
    0x42b25: "FW_DATA_1",
    0x56933: "FW_DATA_2",
}

# 收集 adrp 结果：对每条 adrp，其目标页 = (addr&~0xfff) + imm（imm 是有符号的）
# 同时也看紧随其后的 add（页内偏移）
insns = list(md.disasm(code, TEXT_VA))
for i, insn in enumerate(insns):
    if insn.mnemonic == 'adrp':
        op = insn.operands[1]
        imm = op.imm
        page = (insn.address & ~0xfff) + imm
        # 目标页对齐到 0x1000
        page_aligned = page & ~0xfff
        # 看后一条 add
        add_off = 0
        if i+1 < len(insns) and insns[i+1].mnemonic == 'add':
            a = insns[i+1]
            if a.operands[2].type == ARM64_OP_IMM:
                add_off = a.operands[2].imm
        full = page_aligned + add_off
        for saddr, name in strs.items():
            if full == saddr:
                print("HIT STR 0x%x: adrp@0x%x imm=0x%x add=0x%x -> %s" % (saddr, insn.address, imm, add_off, name))
        for faddr, name in fws.items():
            if full == faddr:
                print("HIT FW 0x%x: adrp@0x%x imm=0x%x add=0x%x -> %s" % (faddr, insn.address, imm, add_off, name))
print("done")
