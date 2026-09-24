#!/usr/bin/env python3
# 读 app tuner init 的浮点常量, 解码 reg 0x05-0x08 等值
import struct

so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()

# 从 dis_tuner_init.py 观察到的浮点常量加载地址 (adrp x8/x9/x10 都是 0x28000 页)
addrs = {
    '0x285b0 (block相关)': 0x285b0,
    '0x28710 (block[5..8]=reg05-08)': 0x28710,
    '0x285c8 (block相关)': 0x285c8,
    '0x28758 (block相关)': 0x28758,
    '0x28558': 0x28558,
    '0x284d0': 0x284d0,
    '0x28498': 0x28498,
    '0x287a8': 0x287a8,
    '0x28490': 0x28490,
    '0x284a0': 0x284a0,
}

for name, addr in addrs.items():
    if addr < len(so):
        d = so[addr:addr+8]
        f = struct.unpack('<d', d)[0]
        print(f"{name}: raw={d.hex()} double={f}")
    else:
        print(f"{name}: 越界")
