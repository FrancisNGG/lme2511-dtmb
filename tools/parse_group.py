import re

log = open('/tmp/usbmon_startup.log').read()

# 匹配 submit 行（含数据）
pat = re.compile(r'(\S+)\s+(\d+)\s+S Bo:1:003:1\s+(-?\d+)\s+(\d+)\s+=\s+([0-9a-f ]+)')

events = []
for m in pat.finditer(log):
    ts = int(m.group(2))
    data = bytes.fromhex(m.group(5).strip())
    events.append((ts, data))

events.sort()

# 读回数据在 Ci/C Bo 响应行？usbmon 的读结果在 C Bo 行。这里只匹配 S 行（submit）。
# 读结果需要看 C 行。补充匹配读完成行。
pat_c = re.compile(r'(\S+)\s+(\d+)\s+C Bo:1:003:1\s+(-?\d+)\s+(\d+)\s+=\s+([0-9a-f ]+)')
for m in pat_c.finditer(log):
    ts = int(m.group(2))
    data = bytes.fromhex(m.group(5).strip())
    events.append((ts, ('C', data)))

events.sort()

def parse(d):
    if isinstance(d, tuple):
        return f"  C读回: {d[1].hex()}"
    if len(d) < 5:
        return f"短包({len(d)}B): {d.hex()}"
    op = d[0]; waddr = d[2]; reg = d[3]
    if op == 0x04: return f"WR_TUNER reg0x{reg:02x} {len(d)-4}B={d[4:].hex()}"
    elif op == 0x05:
        dev = "DEMOD" if waddr == 0x32 else f"DEMOD_ALT({waddr:#x})"
        return f"WR_{dev} reg0x{reg:02x}=0x{d[4]:02x}"
    elif op == 0x85: return f"RD_DEMOD reg0x{reg:02x}"
    elif op == 0x84: return f"RD_TUNER reg0x{reg:02x}"
    elif op == 0x03: return f"EP0: {d.hex()}"
    else: return f"op0x{op:02x}: {d.hex()}"

# 打印第2组(482)和第3组(522)的完整序列(含读)
# 第2组 t 约 2522419450~2522609972, 第3组 t 约 2529349303~2529525740
groups = [
    ("482(第2组)", 2522000000, 2523000000),
    ("522(第3组)", 2529000000, 2530000000),
]
for name, lo, hi in groups:
    print(f"\n===== {name} 完整序列(含读) =====")
    for ts, d in events:
        if lo <= ts <= hi:
            print(f"t={ts} {parse(d)}")
