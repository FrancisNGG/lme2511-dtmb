#!/usr/bin/env python3
# 搜索 app so 里的 tuner init 16 字节块 (找 0x27 0x18 ... 0x54 ... 0x75 模式)
import re

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()

# tuner init block 特征: N_int=0x27(39), frac高=0x18, reg09=0x54, reg0B=0x75
# 搜连续 16 字节, 含 0x27 0x18 开头, 且偏移10处=0x54, 偏移12处=0x75
patterns = [
    ('0x27 0x18 开头', bytes([0x27, 0x18, 0x00, 0x00])),
    ('reg09=0x54', bytes([0x54])),
]

# 搜 0x27 0x18 0x00 0x00
print("=== 搜 0x27 0x18 0x00 0x00 (tuner N_int=39, frac=0x18) ===")
for m in re.finditer(re.escape(b'\x27\x18\x00\x00'), so):
    off = m.start()
    # 打印前后 20 字节
    ctx = so[off:off+20]
    print(f"  0x{off:08x}: " + ' '.join(f'{b:02x}' for b in ctx))

# 搜 0x27 0x18 0x00 0x00 0xXX 0xXX 0x01 0x0a 0x08 0x02 0x54 (完整 init block 特征)
print("\n=== 搜完整 tuner init 特征 (含 0x01 0x0a 0x08 0x02 0x54) ===")
pat2 = bytes([0x27, 0x18, 0x00, 0x00])  # 前面
for m in re.finditer(re.escape(b'\x01\x0a\x08\x02\x54'), so):
    off = m.start()
    ctx = so[off-6:off+8]
    print(f"  0x{off:08x}: " + ' '.join(f'{b:02x}' for b in ctx))
