#!/usr/bin/env python3
# Find vtable-like relocation entries: RELATIVE relocs whose r_offset is in .data.rel.ro
# and whose addend points into .text. Group by (r_offset page) to spot vtables.
import struct

SO = "/tmp/android-extract/lib/arm64-v8a/reference_client.so"
so = open(SO, "rb").read()

RELA_START = 0x6b70
RELA_END   = 0x19290
TEXT_START = 0xb6860
TEXT_END   = 0x1d2f60
DATARELRO_START = 0x1d52b0
DATARELRO_END   = 0x1ddf50

entries = []
for off in range(RELA_START, RELA_END, 24):
    r_offset, r_info, r_addend = struct.unpack_from("<QQQ", so, off)
    if (r_info & 0xffffffff) != 0x403:  # R_AARCH64_RELATIVE
        continue
    if DATARELRO_START <= r_offset < DATARELRO_END and TEXT_START <= r_addend < TEXT_END:
        entries.append((r_offset, r_addend))

# Group consecutive r_offsets (vtables are contiguous 8-byte slots)
entries.sort()
print(f"total RELATIVE relocs text->data.rel.ro: {len(entries)}")
# Find runs where offsets are contiguous
runs = []
cur = []
for i, (off, add) in enumerate(entries):
    if cur and off == cur[-1][0] + 8:
        cur.append((off, add))
    else:
        if cur:
            runs.append(cur)
        cur = [(off, add)]
if cur:
    runs.append(cur)

# Print runs with >= 5 entries (likely vtables), showing function targets
for r in runs:
    if len(r) >= 5:
        base = r[0][0]
        print(f"\n=== vtable run @0x{base:x} ({len(r)} entries) ===")
        for off, add in r:
            print(f"  [+0x{off-base:x}] 0x{add:x}")
