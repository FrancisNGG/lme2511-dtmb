data = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()

# 两份 firmware 候选
fw1 = 0x42B25  # 273157
fw2 = 0x56933  # 354547

def analyze(base, name):
    print("=== %s @ 0x%x ===" % (name, base))
    rom = data[base:base+512]
    # ROM 前 18 字节是 USB 设备描述符
    print("  ROM 前 18B: %s" % rom[:18].hex())
    # 找 ROM 结束（APP 特征 020c400209592200 或类似）
    # 打印 ROM 的尾部（找 APP 边界）
    for off in range(480, 530):
        seg = data[base+off:base+off+8]
        # APP 特征通常以 02 0c 40 开头（LJMP）
        if seg[0] == 0x02 and seg[1] == 0x0c and seg[2] == 0x40:
            print("  APP 特征 @ ROM+%d (0x%x): %s" % (off, off, seg.hex()))
    # 打印 480-512 的内容
    print("  ROM[480:512]: %s" % data[base+480:base+512].hex())
    print("  ROM[496:520]: %s" % data[base+496:base+520].hex())

analyze(fw1, "FW1 (ref 用的那份)")
print()
analyze(fw2, "FW2 (第二份)")
