import re

log = open('/tmp/usbmon_startup.log').read()

# 读请求(OUT submit) 和 读回值(IN complete)
pat_out = re.compile(r'(\S+)\s+(\d+)\s+S Bo:1:003:1\s+(-?\d+)\s+(\d+)\s+=\s+([0-9a-f ]+)')
pat_in  = re.compile(r'(\S+)\s+(\d+)\s+C Bi:1:003:1\s+(-?\d+)\s+(\d+)\s+=\s+([0-9a-f ]+)')

events = []
for m in pat_out.finditer(log):
    ts = int(m.group(2))
    data = bytes.fromhex(m.group(5).strip())
    events.append((ts, 'out', data))
for m in pat_in.finditer(log):
    ts = int(m.group(2))
    data = bytes.fromhex(m.group(5).strip())
    events.append((ts, 'in', data))
events.sort()

# 打印第2组(482)的读回值, 关联读请求
lo, hi = 2522000000, 2523000000
print("===== 482 组: 读请求 + 读回值 =====")
pending_reg = None
for ts, kind, d in events:
    if not (lo <= ts <= hi):
        continue
    if kind == 'out':
        if len(d) >= 5 and d[0] == 0x85:
            reg = d[3]
            byte4 = d[4]
            print(f"t={ts} 读请求 reg0x{reg:02x} byte4=0x{byte4:02x}")
            pending_reg = reg
        elif len(d) >= 5 and d[0] == 0x05:
            dev = "DEMOD" if d[2]==0x32 else f"ALT({d[2]:#x})"
            print(f"t={ts} 写 {dev} reg0x{d[3]:02x}=0x{d[4]:02x}")
        elif len(d) >= 5 and d[0] == 0x04:
            print(f"t={ts} 写TUNER reg0x{d[3]:02x} {len(d)-4}B={d[4:].hex()}")
    else:
        # 读回值
        print(f"t={ts}   读回 = {d.hex()}  (reg0x{pending_reg:02x})" if pending_reg else f"t={ts}   读回 = {d.hex()}")
