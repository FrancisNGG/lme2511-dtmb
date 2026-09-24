#!/usr/bin/env python3
# Parse .rela.dyn and find entries whose addend matches given function addresses
import struct, sys

SO = "/tmp/android-extract/lib/arm64-v8a/reference_client.so"
so = open(SO, "rb").read()

# .rela.dyn: VA 0x6b70, offset 0x6b70 (VA==offset), size = next section 0x19290 - 0x6b70
RELA_START = 0x6b70
RELA_END   = 0x19290

targets = set(int(a,16) for a in sys.argv[1:])

# map addend -> list of (r_offset)
found = {t: [] for t in targets}
for off in range(RELA_START, RELA_END, 24):
    r_offset, r_info, r_addend = struct.unpack_from("<QQQ", so, off)
    if r_addend in targets:
        found[r_addend].append((off, r_offset, r_info))

for t in sorted(targets):
    print(f"--- addend 0x{t:x} (function pointer target) ---")
    if not found[t]:
        print("  (none)")
    for off, r_offset, r_info in found[t]:
        typ = r_info & 0xffffffff
        print(f"  reloc@0x{off:x}: r_offset=0x{r_offset:x} r_info=0x{r_info:x} (type=0x{typ:x})")
    print()
