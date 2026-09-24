import sys, struct
sys.path.insert(0, '/tmp/revenv/lib/python3.11/site-packages')
from capstone import *
from capstone.arm64 import *
so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

TEXT_START = 0xb6860
TEXT_END   = 0x1d2f60

# 搜索两种调用 demod_resync 的方式:
# 1) bl 0x100afc (thunk -> 虚表[0x28])
# 2) 读虚表基址后 ldr x?, [x?, #0x28] 再 blr
# 也搜 bl 0x100b08 (thunk -> 虚表[0x30] -> 0x100afc -> [0x28])

print("=== 搜索 bl 到 thunk 0x100afc / 0x100b08 (间接调 demod_resync) ===")
code = so[TEXT_START:TEXT_END]
bl_targets = set()
for ins in md.disasm(code, TEXT_START):
    if ins.mnemonic == 'bl':
        tgt = ins.operands[0].imm
        if tgt in (0x100afc, 0x100b08):
            bl_targets.add(ins.address)
            print(f"  {ins.address:#x}: bl 0x{tgt:x}")

print(f"\n共 {len(bl_targets)} 处间接调用 demod_resync thunk")
