C1 = 0x00d79435e50d7944
C2 = 0x0d79435e50d79436

def umulh(a, b):
    return (a * b) >> 64

freq_mhz = 522
w20 = freq_mhz * 1000  # kHz
w8 = w20 * 1000
x9 = 0
while (w8 >> x9) > 1:
    x9 += 1
x25 = x9 - 1
print(f"w20={w20} w8={w8} x25={x25}")

# x25 > 4
x26 = w8 << 1
w21 = w20 << 1
print(f"x26={x26} w21={w21}")

x27 = w21 * 5
x8 = x27 << 2
x22 = umulh(x8, C1)
print(f"x27={x27} x22(1st)={x22:#x}")

reg0 = 0x0e
w21_val = (0x40 | (reg0 & 0x1f)) if x22 < 0x43 else (reg0 & 0x1f)
print(f"w21_val={w21_val:#x}")

v1a = ((x22 >> 8) & 0xff) | 0xfc
v1b = x22 & 0xff
print(f"0x1a={v1a:#x} 0x1b={v1b:#x}")

x8_2 = x27 << 0x12
x22_2 = umulh(x8_2, C2)
print(f"x8_2={x8_2} x22_2={x22_2:#x}")

hi = 1 if x26 > 0x13c67f else 0
nibble = (x22_2 >> 16) & 0x0f
base = (hi << 7) | (x25 << 4)
w2_1c = base | nibble
print(f"hi={hi} nibble={nibble:#x} base={base:#x} (x25<<4={x25<<4:#x}) w2_1c={w2_1c:#x} 0x1c_low8={w2_1c & 0xff:#x}")

v1d = (x22_2 >> 8) & 0xff
v1e = x22_2 & 0xff
print(f"0x1d={v1d:#x} 0x1e={v1e:#x}")
