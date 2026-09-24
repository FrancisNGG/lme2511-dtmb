import sys
sys.path.insert(0, '/tmp/revenv/lib/python3.11/site-packages')
from capstone import *
from capstone.arm64 import *
so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

TEXT_START = 0xb6860
TEXT_END   = 0x1d2f60

# 找 ldr x?, [x?, #0x28] (非 sp) 后面紧跟 blr 的序列
code = so[TEXT_START:TEXT_END]
insns = list(md.disasm(code, TEXT_START))

for i, ins in enumerate(insns):
    if ins.mnemonic == 'ldr' and '#0x28]' in ins.op_str:
        # 排除栈偏移 [sp, #0x28]
        if 'sp' in ins.op_str:
            continue
        # 看后面 3 条指令内是否有 blr
        for j in range(i+1, min(i+4, len(insns))):
            if insns[j].mnemonic == 'blr':
                print(f"{ins.address:#x}: {ins.mnemonic} {ins.op_str}  ->  {insns[j].address:#x}: blr {insns[j].op_str}")
                break
            if insns[j].mnemonic in ('bl', 'b', 'ret', 'cbz', 'cbnz'):
                break
