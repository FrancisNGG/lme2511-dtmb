import sys, struct
sys.path.insert(0, '/tmp/revenv/lib/python3.11/site-packages')
from capstone import *
from capstone.arm64 import *
so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

# 读 demod 虚表 @0x1d7a98 (子代理说这里) 的各个方法指针
base = 0x1d7a98
print("=== 虚表 @0x1d7a98 (每个 8 字节) ===")
for off in range(0, 0x90, 8):
    addr = base + off
    val = struct.unpack('<Q', so[addr:addr+8])[0]
    note = ""
    if val == 0x11979c: note = " <- demod init @0x11979c"
    if val == 0x119b74: note = " <- demod_resync @0x119b74"
    print(f"[+0x{off:02x}] @0x{addr:x} = 0x{val:x}{note}")

# 也读 0x1d8400 (子代理提的"前端 vtable 0x1d8400[0x88]")
print("\n=== 虚表 @0x1d8400 ===")
for off in range(0, 0xa0, 8):
    addr = 0x1d8400 + off
    val = struct.unpack('<Q', so[addr:addr+8])[0]
    print(f"[+0x{off:02x}] @0x{addr:x} = 0x{val:x}")
