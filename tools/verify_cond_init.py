import sys
sys.path.insert(0, '/tmp/revenv/lib/python3.11/site-packages')
from capstone import *
from capstone.arm64 import *
so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

# carrier_config @0x119090, disassemble up to 0x1191d0 to see 0x119110 branch
base = 0x119090
end  = 0x1191d0
code = so[base:end]
for ins in md.disasm(code, base):
    mark = ""
    if ins.address == 0x119110: mark = "  <== bl demod_full_init"
    if ins.address in (0x119090,0x1190a0,0x1190b0,0x1190c0,0x1190d0,0x1190e0,0x1190f0,0x119100,0x119110,0x119120,0x119130,0x119140):
        print(f"--- {ins.address:#x} ---")
    print(f"{ins.address:#x}: {ins.mnemonic}\t{ins.op_str}{mark}")
