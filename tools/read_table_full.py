#!/usr/bin/env python3
# 读 app 表 @0x3fc54 的完整内容 (确认 27 vs 28 对, 是否含 reg 0x00)
so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
BASE = 0x3fc54
print("=== app 寄存器表 @0x3fc54 (读 60 字节 = 30 对) ===")
for i in range(30):
    off = BASE + i*2
    reg = so[off]
    val = so[off+1]
    mark = "  <-- 循环 x22=0..52 写到这里为止 (第27对)" if i == 26 else ""
    if i >= 27:
        mark = "  <-- 循环外 (不写)"
    print(f"  第{i+1:2d}对: reg 0x{reg:02x} = 0x{val:02x}{mark}")
