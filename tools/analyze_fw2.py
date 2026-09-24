data = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()

fw1 = 0x42B05  # 273157
fw2 = 0x568F3  # 354547

def parse_usb_desc(base, name):
    print("=== %s @ 0x%x ===" % (name, base))
    rom = data[base:base+512]
    # 设备描述符
    bLength = rom[0]
    idVendor = rom[8] | (rom[9] << 8)
    idProduct = rom[10] | (rom[11] << 8)
    print("  bLength=%d idVendor=0x%04x idProduct=0x%04x" % (bLength, idVendor, idProduct))
    print("  前 32B: %s" % rom[:32].hex())
    # ROM 尾部（找 APP 边界）
    print("  ROM[496:520]: %s" % data[base+496:base+520].hex())
    # 找 APP 特征（LJMP 02 0c 40）
    for off in range(490, 520):
        seg = data[base+off:base+off+3]
        if seg == bytes.fromhex('020c40'):
            print("  APP 特征(LJMP) @ ROM+%d" % off)

parse_usb_desc(fw1, "FW1")
print()
parse_usb_desc(fw2, "FW2")

# 第二份的 APP 特征（可能不同）
print("\n第二份 ROM 之后的内容:")
print("  FW2[500:516]: %s" % data[fw2+500:fw2+516].hex())
