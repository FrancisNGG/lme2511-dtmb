from capstone import *
from capstone.arm64 import *
import re

so = '/tmp/android-extract/lib/arm64-v8a/reference_client.so'
data = open(so,'rb').read()

# 关键字符串
keys = [
    b"raw split firmware unavailable",
    b"upload raw split variant=%s rom=%zu fw=%zu",
    b"firmware size %zu not aligned to chunk %d",
    b"Lme2510Driver::open",
    b"LME2510C cold boot: firmware uploaded, awaiting re-enumeration",
    b"raw split firmware upload requires cold bootloader PID",
]

for k in keys:
    off = data.find(k)
    if off >= 0:
        # .rodata VA = offset
        print("str %-55s @ offset 0x%x VA 0x%x" % (k.decode()[:50], off, off))
    else:
        print("str %-55s NOT FOUND" % k.decode()[:50])
