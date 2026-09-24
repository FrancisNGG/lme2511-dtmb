import sys
sys.path.insert(0, '/tmp/revenv/lib/python3.11/site-packages')
from capstone import *
from capstone.arm64 import *
so = open('/tmp/android-extract/lib/arm64-v8a/reference_client.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True

# 主调谐函数 @0x13700c, 反汇编到 0x1371e0, 标注所有 bl 目标
base = 0x137000
end  = 0x1371e0
code = so[base:end]

def resolve(addr):
    # 尝试读目标处的符号性信息 (没有符号, 只能看 bl 目标地址)
    return f"0x{addr:x}"

for ins in md.disasm(code, base):
    mark = ""
    if ins.mnemonic == 'bl':
        tgt = ins.operands[0].imm
        mark = f"  <== bl {resolve(tgt)}"
    if ins.mnemonic == 'blr':
        mark = f"  <== blr {ins.op_str}"
    print(f"{ins.address:#x}: {ins.mnemonic}\t{ins.op_str}{mark}")
