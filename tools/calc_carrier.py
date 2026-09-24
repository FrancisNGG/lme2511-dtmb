# 模拟 app @0x119090 demod 载波频率配置函数, 计算各频点的寄存器值
# 关键: 定点乘除 umulh(a,b) = floor(a*b / 2^64)

C1 = 0x00d79435e50d7944  # @0x1191b8-0x1191d8
C2 = 0x0d79435e50d79436  # @0x119270-0x119294

def umulh(a, b):
    return (a * b) >> 64

def bfxil(val, insert, lsb, width):
    mask = ((1 << width) - 1) << lsb
    return (val & ~mask) | ((insert & ((1 << width) - 1)) << lsb)

def calc(freq_mhz, reg0=0x0e):
    w20 = freq_mhz * 1000  # kHz
    # x25 = floor(log2(w20 * 1000))
    w8 = w20 * 1000
    x9 = 0
    while (w8 >> x9) > 1:
        x9 += 1
    x25 = x9 - 1  # 0x119134: sub x25, x9, #1

    if x25 > 4:
        x26 = w8 << 1
        w21 = w20 << 1
    else:
        w9 = 0x10 >> x25
        w26 = w9 * w8
        w21 = w9 * w20

    # 读 reg 0x00 -> w8 (0x1191a0 读, 假设 reg0)
    w8 = reg0

    # 0x1191b4-0x1191f4: 第一处 x22
    x27 = w21 + w21 * 4  # w21 * 5  (0x1191c0: add x27, x8, w21 uxtw#2  => w21 + w21*4)
    x8 = x27 << 2
    x22 = umulh(x8, C1)

    # w21 = (x22 < 0x43) ? (0x40 | (w8 & 0x1f)) : (w8 & 0x1f)
    w9_val = bfxil(0x40, w8, 0, 5)
    w8_and = w8 & 0x1f
    w21 = w9_val if x22 < 0x43 else w8_and

    # 写 0x15=0x3d, 0x19=0x02, 0x27=0(w2=0), 0x2f=w21
    regs = {}
    regs[0x15] = 0x3d
    regs[0x19] = 0x02
    regs[0x27] = 0x00
    regs[0x2f] = w21 & 0xff

    # 0x119228-0x119254: 0x1a 写
    # 读 reg 0x00 再次 -> w8 (0x119214-0x119220 读)
    w8 = reg0
    x10 = (x22 >> 8) & 0xffffff  # ubfx x10, x22, #8, #0x18
    w9 = (~0x13) & 0xffffffff  # movn w9, #0x13 => 0xffffffec
    tst = w8 & 0x38
    w8_sel = w9 if tst == 0 else 0
    # strb w8_sel -> [x24+0x12d]
    state_12d = w8_sel & 0xff
    # w2 = x10 | 0xfffffffc
    w2_1a = (x10 | 0xfffffffc) & 0xff
    regs[0x1a] = w2_1a

    # 0x11925c-0x119264: 0x1b = w22 (第一处 x22 低字节)
    regs[0x1b] = x22 & 0xff

    # 0x119270-0x1192ac: 第二处 x22 (0x1c 写)
    x8_2 = x27 << 0x12
    x22_2 = umulh(x8_2, C2)
    # cmp x26, 0x13c67f (0x11927c: movz w9,#0xc67f; 0x119280: movk w9,#0x13 lsl#16 => 0x13c67f)
    w9_cmp = 0x13c67f
    hi = 1 if x26 > w9_cmp else 0
    w2_1c = (hi << 7) | (x25 << 4) | ((x22_2 >> 16) & 0x0f)
    regs[0x1c] = w2_1c & 0xff

    # 0x1192b4-0x1192c0: 0x1d = x22_2 >> 8
    regs[0x1d] = (x22_2 >> 8) & 0xff

    # 0x1192c8-0x1192d0: 0x1e = x22_2 (低字节)
    regs[0x1e] = x22_2 & 0xff

    # 0x1192dc-0x119310: 0x2f = w21, 0x2f = w21|0x80, 0x2f = w21
    # (最终 0x2f = w21)

    # 0x119318-0x119324: 0x27 = state_12d
    regs[0x27] = state_12d

    # 0x119328-0x119340: 如果 w20 >= 0x191 (401): 0x29 = 0xbf
    regs[0x29] = 0xbf if w20 >= 0x191 else None

    return regs

for f in [482, 522, 538, 586, 602]:
    r = calc(f)
    keys = sorted(r.keys())
    vals = "  ".join(f"0x{k:02x}={r[k]:02x}" for k in keys if r[k] is not None)
    print(f"{f} MHz: {vals}")
    print(f"    (x25 相关, 0x2f 值=0x{r[0x2f]:02x})")
