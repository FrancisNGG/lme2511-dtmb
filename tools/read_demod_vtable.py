import struct
SO = "/tmp/android-extract/lib/arm64-v8a/reference_client.so"
so = open(SO, "rb").read()
RELA_START = 0x6b70
RELA_END   = 0x19290

# demod 虚表 @0x1d7a98, 找 r_offset 在该范围的所有 reloc 项
print("=== demod 虚表 @0x1d7a98 各 slot 的函数 (经 rela.dyn 解析) ===")
for off in range(RELA_START, RELA_END, 24):
    r_offset, r_info, r_addend = struct.unpack_from("<QQQ", so, off)
    if (r_info & 0xffffffff) != 0x403:
        continue
    if 0x1d7a98 <= r_offset < 0x1d7b50:
        slot = r_offset - 0x1d7a98
        print(f"  [+0x{slot:02x}] @0x{r_offset:x} -> 0x{r_addend:x}")
