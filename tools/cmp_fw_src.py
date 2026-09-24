data = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
fw = open('/lib/firmware/dvb-usb-ref.fw.bak-patched','rb').read()  # ref 补丁版 5348

print("ref 补丁版大小: %d" % len(fw))
rom = fw[:512]
app = fw[512:5348]

# 候选 ROM 源
candidates_rom = {
    'entry2_ROM(0x42b05,500)': (0x42b05, 500),
    'entry3_ROM(0x568f3,512)': (0x568f3, 512),
}
# 候选 APP 源
candidates_app = {
    'entry2_APP(0x42cf9,4800)': (0x42cf9, 4800),
    'entry4_APP(0x43fb9,4836)': (0x43fb9, 4836),
}

for name, (base, ln) in candidates_rom.items():
    seg = data[base:base+512]
    # 对比前 500 字节（ref ROM 前 500 应该匹配）
    same500 = sum(1 for i in range(500) if seg[i] == rom[i])
    # 对比全部 512
    same512 = sum(1 for i in range(512) if seg[i] == rom[i])
    print("ROM 源 %s: 前500匹配 %d/500, 全512匹配 %d/512" % (name, same500, same512))

print()
for name, (base, ln) in candidates_app.items():
    seg = data[base:base+ln]
    same = sum(1 for i in range(min(ln, 4836)) if seg[i] == app[i])
    print("APP 源 %s (%d字节): 匹配 %d/4836" % (name, ln, same))
