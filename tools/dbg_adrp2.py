import struct
data = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()

insn = struct.unpack('<I', data[0xb6864:0xb6868])[0]
print("0xb6864 insn: 0x%08x" % insn)

immlo = (insn >> 29) & 0x3
immhi = (insn >> 5) & 0x7ffff
rd = insn & 0x1f
imm21 = (immhi << 2) | immlo
if imm21 & (1 << 20):
    imm21 -= (1 << 21)
print("immlo=%d immhi=0x%x imm21=0x%x(%d) rd=x%d" % (immlo, immhi, imm21, imm21, rd))

pc = 0xb6864
target = (pc & ~0xfff) + (imm21 << 12)
print("target page = 0x%x" % target)

add_insn = struct.unpack('<I', data[0xb6868:0xb686c])[0]
imm12 = (add_insn >> 10) & 0xfff
print("add imm12 = 0x%x, full = 0x%x" % (imm12, target + imm12))
