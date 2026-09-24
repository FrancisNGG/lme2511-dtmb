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

# 字符串地址（VA）
strs = {
    0x33658: "raw split firmware unavailable",
    0x358b4: "upload raw split variant=%s rom=%zu fw=%zu",
    0x2ff5d: "firmware size not aligned to chunk",
    0x2a0b4: "Lme2510Driver::open",
    0x33f51: "LME2510C cold boot uploaded",
    0x2b2b4: "raw split requires cold bootloader",
}

# 先收集所有 ADRP 指令的 (地址, 目标页)
adrp_pages = {}
for insn in md.disasm(code, TEXT_VA):
    if insn.mnemonic == 'adrp':
        op = insn.operands[1]
        page = (insn.address & ~0xfff) + (op.imm << 12)
        adrp_pages[insn.address] = page

# 找引用这些字符串的 ADRP
for addr, page in adrp_pages.items():
    for saddr, name in strs.items():
        if page == (saddr & ~0xfff):
            print("ADRP 0x%x -> page 0x%x (str 0x%x) %s" % (addr, page, saddr, name))
