import sys
sys.path.insert(0, '/tmp/revenv/lib/python3.11/site-packages')
from capstone import *
from capstone.arm64 import *
so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

def dis(addr, size, label):
    print(f"\n===== {label} @{addr:#x} =====")
    code = so[addr:addr+size]
    for ins in md.disasm(code, addr):
        mark = ""
        if ins.mnemonic == 'bl':
            mark = f"  <== bl 0x{ins.operands[0].imm:x}"
        if ins.mnemonic == 'blr':
            mark = f"  <== blr {ins.op_str}"
        print(f"{ins.address:#x}: {ins.mnemonic}\t{ins.op_str}{mark}")

# lock_config @0x1384d0, 看它怎么调 0x1388cc
dis(0x1384d0, 0x220, "lock_config 0x1384d0")
