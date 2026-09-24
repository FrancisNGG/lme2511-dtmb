import re

log = open('/tmp/usbmon_startup.log').read()

# 匹配带时间戳的 submit 行: <ts> S Bo:1:003:1 <status> <len> = <hex>
# usbmon 格式: ffff... 1234567890 S Bo:1:003:1 -115 5 = 0504320c00
pat = re.compile(r'(\S+)\s+(\d+)\s+S Bo:1:003:1\s+(-?\d+)\s+(\d+)\s+=\s+([0-9a-f ]+)')

events = []
for m in pat.finditer(log):
    ts = m.group(2)
    size = int(m.group(4))
    hexstr = m.group(5).strip()
    data = bytes.fromhex(hexstr)
    events.append((int(ts), data))

events.sort()

def parse(d):
    if len(d) < 5:
        return f"短包({len(d)}B): {d.hex()}"
    op = d[0]
    waddr = d[2]
    reg = d[3]
    if op == 0x04:  # 写 tuner multi
        return f"WR_TUNER reg0x{reg:02x} {len(d)-4}B={d[4:].hex()}"
    elif op == 0x05:  # 写 demod single
        dev = "DEMOD" if waddr == 0x32 else f"DEMOD_ALT({waddr:#x})"
        val = d[4]
        return f"WR_{dev} reg0x{reg:02x}=0x{val:02x}"
    elif op == 0x85:
        return f"RD_DEMOD reg0x{reg:02x}"
    elif op == 0x84:
        return f"RD_TUNER reg0x{reg:02x}"
    elif op == 0x03:
        return f"EP0 0x03: {d.hex()}"
    else:
        return f"op0x{op:02x}: {d.hex()}"

writes = [(ts, d) for ts, d in events if len(d) >= 5 and d[0] in (0x04, 0x05)]
print(f"写操作总数: {len(writes)}\n")
for i, (ts, d) in enumerate(writes):
    print(f"[{i:3d}] t={ts} {parse(d)}")
