import re, sys

# 解析 usbmon 日志，提取端点1 bulk OUT 的写/读请求
log = open('/tmp/usbmon_522.log').read()

# 找所有 S Bo:1:003:1 ... = <hex> 的 submit 行（带数据）
pattern = re.compile(r'S Bo:1:003:1 -115 (\d+) = ([0-9a-f ]+)')
events = []
for m in pattern.finditer(log):
    size = int(m.group(1))
    hexstr = m.group(2).strip()
    data = bytes.fromhex(hexstr)
    events.append(data)

print(f"共 {len(events)} 条端点1 OUT 请求\n")

# 解析每条
def parse(d):
    if len(d) < 4:
        return f"  短包({len(d)}B): {d.hex()}"
    op = d[0]
    if op == 0x04:  # WR_MULTI tuner
        waddr = d[2]
        reg = d[3]
        payload = d[4:]
        return f"写TUNER(waddr={waddr:#x}) reg 0x{reg:02x} + {len(payload)}B = {payload.hex()}"
    elif op == 0x05:  # WR_SINGLE demod
        waddr = d[2]
        reg = d[3]
        val = d[4]
        dev = "DEMOD" if waddr == 0x32 else f"DEMOD_ALT(waddr={waddr:#x})"
        return f"写{dev} reg 0x{reg:02x} = 0x{val:02x}"
    elif op == 0x85:  # RD_DEMOD
        waddr = d[2]
        reg = d[3]
        return f"读DEMOD reg 0x{reg:02x}"
    elif op == 0x84:  # RD_TUNER
        waddr = d[2]
        reg = d[3]
        return f"读TUNER reg 0x{reg:02x}"
    elif op == 0x03:
        return f"EP0/其他 0x03: {d.hex()}"
    else:
        return f"未知op 0x{op:02x}: {d.hex()}"

# 只打印写操作（调谐序列关键），跳过纯读（轮询）
writes = [e for e in events if len(e) >= 4 and e[0] in (0x04, 0x05)]
print(f"=== 写操作序列（{len(writes)} 条，跳过轮询读） ===")
for i, e in enumerate(writes):
    print(f"[{i:3d}] {parse(e)}")
