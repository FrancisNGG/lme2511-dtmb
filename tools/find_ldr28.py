import sys
sys.path.insert(0, '/tmp/revenv/lib/python3.11/site-packages')
from capstone import *
from capstone.arm64 import *
so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

TEXT_START = 0xb6860
TEXT_END   = 0x1d2f60

# 搜索 ldr 带 #0x28 偏移 (可能是读虚表[0x28] = demod_resync)
print("=== ldr x?, [x?, #0x28] (读虚表 slot 0x28) ===")
code = so[TEXT_START:TEXT_END]
hits = []
for ins in md.disasm(code, TEXT_START):
    if ins.mnemonic == 'ldr' and '#0x28]' in ins.op_str:
        hits.append(ins)

for ins in hits:
    print(f"  {ins.address:#x}: {ins.mnemonic}\t{ins.op_str}")

print(f"\n共 {len(hits)} 处")
