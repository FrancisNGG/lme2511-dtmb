import sys
sys.path.insert(0, '/tmp/revenv/lib/python3.11/site-packages')
from capstone import *
from capstone.arm64 import *
so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

# 反汇编所有 thunk @0x100afc ~ 0x100b80
code = so[0x100af0:0x100b90]
for ins in md.disasm(code, 0x100af0):
    print(f"{ins.address:#x}: {ins.mnemonic}\t{ins.op_str}")
