# lme2511-dtmb — 第一波道 DTMB USB 电视棒 Linux 驱动

基于 **dvb-usb-v2** 框架的 Linux 内核驱动，支持 **第一波道 DTMB** USB 电视棒
（VID:PID `0x3344:0x1120`，LME2511 + LGS8GL5 + MAX2165）。

**基于对配套客户端 USB 通信的抓包（usbmon）逐字节逆向实现**，非官方/第三方
驱动移植。切台与启动初始化序列均照抄实测抓包。

## 硬件信息

| 功能       | 芯片                     | 说明               |
|------------|--------------------------|--------------------|
| USB 桥接   | **LME2511**              | MCU + USB + I2C 桥 |
| 解调器     | **LGS8GL5**（LG）         | DTMB（DMB-TH）      |
| 调谐器     | **MAX2165**（Maxim）      | 硅调谐器            |

- **接口**：USB 2.0 High-Speed（480 Mbps）
- **USB ID**：`3344:1120`（与 LME 驱动 `dvb_usb_lmedm04` 共用）
- **TS 端点**：暖状态后 EP 0x88（BULK IN）
- **命令端点**：EP 0x01（BULK OUT）/ EP 0x81（BULK IN）
- **状态端点**：EP 0x8A（INTERRUPT IN）

由于没有可用的 Linux 驱动，本项目通过 USB 抓包（usbmon）逆向能正常工作的
配套客户端，逐字节还原 LME2511 + LGS8GL5 + MAX2165 的 I2C 寄存器序列，
在 Linux 下实现 5 频点全锁。

## 固件

电视棒有两段式固件，由 MCU（LME2511）加载：

```
firmware/rom.dat (512 B) + firmware/fw_new.bin (4836 B) → dvb-usb-lme2511.fw (5348 B)
  ↑ ROM 区 (偏移 0)        ↑ APP 区 (偏移 512)
```

合并后的固件文件需安装到 `/lib/firmware/dvb-usb-lme2511.fw`。
ROM 区包含 MCU 重启后要呈现的 USB 设备描述符；
APP 区包含 I2C 桥和 TS 流的运行固件。

> **固件是芯片厂商 (LME/Legend) 的固件 blob**，版权归厂商，**非本项目原创代码**，
> 也不归本项目作者。它与配套客户端内嵌固件、内核
> `dvb-usb-lmedm04` 驱动所用固件**逐字节相同**（同一份厂商固件）。

## 依赖

### 内核要求

- Linux **≥ 5.15**（实测于 Ubuntu 24.04，内核 7.0.0-31）
- 必须提供 `dvb-core` 和 `dvb-usb-v2` 内核模块

### 标准桌面 Linux

包 `linux-modules-extra`（或等效包）通常已包含 DVB 模块：

```bash
sudo modprobe dvb_usb_v2    # 自动拉入 dvb_core
```

### 嵌入式 / 单板电脑（Armbian 等）

Armbian 的 sunxi64 内核默认没有启用 DVB 支持
（`CONFIG_MEDIA_DIGITAL_TV_SUPPORT` 被禁用），需从内核源码将
`dvb-core` 和 `dvb-usb-v2` 编译为外部模块。构建过程见下方说明。

### 编译工具

- `gcc`、`make`、`linux-headers-$(uname -r)`

## 构建

### 第一步：编译 `dvb-core` 和 `dvb-usb-v2`（如果发行版已提供，可跳过此步）

```bash
# 下载内核源码（只解压 DVB 相关目录）
KVER=<kernel-version>  # 与运行内核版本一致（如 6.8.0）
curl -o linux-$KVER.tar.xz https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KVER.tar.xz
tar xf linux-$KVER.tar.xz --wildcards \
  "linux-$KVER/drivers/media/dvb-core/*" \
  "linux-$KVER/drivers/media/usb/dvb-usb-v2/*" \
  "linux-$KVER/include/media/*" \
  "linux-$KVER/include/uapi/linux/dvb/*"

# 建立构建目录
mkdir dvb_build && cd dvb_build
ln -sf ../linux-$KVER/drivers/media/dvb-core dvb-core
ln -sf ../linux-$KVER/drivers/media/usb/dvb-usb-v2 dvb-usb-v2
cat > Kbuild << 'EOF'
ccflags-y += -DCONFIG_DVB_CORE_MODULE
ccflags-y += -DCONFIG_DVB_NET=1
ccflags-y += -DCONFIG_DVB_USB_V2_MODULE
ccflags-y += -DCONFIG_MEDIA_DIGITAL_TV_SUPPORT=1

obj-m += dvb-core.o
dvb-core-y := dvb-core/dvbdev.o dvb-core/dmxdev.o dvb-core/dvb_demux.o \
              dvb-core/dvb_ca_en50221.o dvb-core/dvb_frontend.o \
              dvb-core/dvb_net.o dvb-core/dvb_ringbuffer.o

obj-m += dvb_usb_v2.o
dvb_usb_v2-y := dvb-usb-v2/dvb_usb_core.o dvb-usb-v2/dvb_usb_urb.o \
                dvb-usb-v2/usb_urb.o
EOF

make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
```

### 第二步：编译 `lme2511`

```bash
cd lme2511_driver

# 如果第一步手动编译了 DVB 模块（开发板场景）：
make -C /lib/modules/$(uname -r)/build M=$(pwd) \
  KBUILD_EXTRA_SYMBOLS=/path/to/dvb_build/Module.symvers modules

# 如果发行版已自带 DVB 模块（桌面 Linux）：
make
```

Makefile 的 `ccflags-y` 中已包含 `-DCONFIG_DVB_NET=1` 等定义，确保
`struct dvb_net` 大小与 `dvb_usb_v2` 编译时一致。在 DVB 模块从内核源码
外部编译的环境中，此定义至关重要。

## 安装

```bash
# 安装固件
cat firmware/rom.dat firmware/fw_new.bin > dvb-usb-lme2511.fw
sudo cp dvb-usb-lme2511.fw /lib/firmware/

# 安装 DVB 模块（仅当从源码编译时需要）
sudo cp dvb-core.ko dvb_usb_v2.ko /lib/modules/$(uname -r)/extra/

# 安装驱动模块
sudo cp lme2511.ko /lib/modules/$(uname -r)/extra/

# 更新模块依赖
sudo depmod -a

# 屏蔽冲突驱动（PID:VID 与 lmedm04 共享）
echo 'blacklist dvb_usb_lmedm04' | sudo tee /etc/modprobe.d/lme2511.conf
echo 'install dvb_usb_lmedm04 /bin/false' | sudo tee -a /etc/modprobe.d/lme2511.conf
```

## 加载

安装后插入电视棒会自动加载（depmod 生成的 USB ID 别名）：

```
alias usb:v3344p1120d*dc*dsc*dp*ic*isc*ip*in* lme2511
```

手动加载命令：

```bash
sudo modprobe dvb_usb_v2       # 自动拉入 dvb_core
sudo modprobe lme2511         # 绑定至电视棒

# 或按顺序使用 insmod：
sudo insmod dvb-core.ko
sudo insmod dvb_usb_v2.ko
sudo insmod lme2511.ko
```

## 启动流程

```
插入电视棒
  → 检测到冷状态（无 EP 0x88）
  → 通过 EP1 BULK 上传 ROM（11 块）+ APP（97 块）
  → 发送 MCU 重启命令 (0x8A 0x00)
  → USB 断开 / 重新枚举
  → 检测到暖状态（alt-setting 1 中存在 EP 0x88）
  → 注册 DVB adapter
  → 初始化 demod（LGS8GL5）+ tuner（MAX2165）
  → 创建设备节点 /dev/dvb/adapter0/{frontend0,dvr0,demux0,net0}
```

## 实测结果

香港 5 个 DTMB 频点全部锁定（2026-09-24，Ubuntu 24.04 内核 7.0.0-31）：

| 频点 | 频道 | 锁定状态 |
|------|------|----------|
| 522 MHz | RTHK31 | `Lock (0x1b)`，C/N ≈ 57%，UCB 有数据 |
| 482 MHz | HOY76 | `Lock (0x1b)`，TS 流有数据 |
| 538 MHz | RTHK35 | `Lock (0x1b)`，TS 流有数据 |
| 586 MHz | Pearl | `Lock (0x1b)`，TS 流有数据 |
| 602 MHz | Jade | `Lock (0x1b)`，TS 流有数据 |

测锁用流模式（`dvbv5-zap` 不带 `-P`；带 `-P` 不流 TS 会导致 demod 周期性假失锁）：

```bash
# 频道配置（522MHz 为例；DELIVERY_SYSTEM 用 DVBT）
cat > /tmp/522.conf << 'EOF'
[RTHK31]
	DELIVERY_SYSTEM = DVBT
	FREQUENCY = 522000000
	BANDWIDTH_HZ = 8000000
EOF

# 锁定验证（流模式）
dvbv5-zap -a 0 -c /tmp/522.conf RTHK31
```

弱信号频点（482/538/586/602）C/N 显示 0.00% 是真实信号质量，不影响锁定和 TS 流。

## 冷启动上传协议

```
数据块格式：[header 1B] [count=N-1 1B] [data N] [checksum 1B]
  每块 N = 50 字节（最后一块可能不足 50）
  ROM: 中间块=0x01, 末块=0x81   （11 块, 512 B）
  APP: 中间块=0x02, 末块=0x82   （97 块, 4836 B）
  ACK: 从 EP 0x81 读取 1 字节 → 0x88 或 0x77 表示成功
  MCU 重启: 向 EP 0x01 写入 {0x8A, 0x00}
```

## 注意事项

### 与 `dvb_usb_lmedm04` 冲突

此电视棒与内核自带的 LME 驱动 `dvb_usb_lmedm04` 共享 VID/PID `3344:1120`。
LME 驱动会认领此设备但无法正常工作。**必须屏蔽 `dvb_usb_lmedm04`** 后才能
加载本驱动。

### 信号强度 / C/N 上报

锁定判定用 I2C 读 `0x4B`（bit7 = carrier 锁）和 `0xA4`（bit0 = FEC lock）。
信号强度 = `0x4B` 低 7 位；SNR/C/N = `0x95` 噪声寄存器。强信号频点（522）
C/N ≈ 57%；弱信号频点（482/538/586/602）C/N 显示 0.00% 是真实信号质量
（`0x95` 读回 0），不影响锁定和 TS 流。EP 0x8A 中断状态包在 TS 流期间不可用
（MCU 总线冲突），故流时信号读取用录流前缓存值。

### `struct dvb_net` 大小不一致

当 DVB 模块从内核源码以 `CONFIG_DVB_NET` 定义编译时，`struct dvb_usb_adapter`
中的 `struct dvb_net` 占约 128 字节。未定义该宏时仅占 8 字节（单个指针）。
这会改变 `struct dvb_usb_device` 中 `d->priv` 的偏移量。本仓库 Makefile 已配
置匹配的 `CONFIG` 定义，使用者无需额外处理。

## 已测试平台

| 平台                    | 内核              | USB 主机 | 状态     |
|-------------------------|-------------------|----------|----------|
| Ubuntu 24.04 | 7.0.0-31      | xHCI     | ✓ 5 频点全锁 |

## 目录结构

```
lme2511-dtmb/
├── src/                     # 驱动源码
│   ├── lme2511_core.c       # 主模块 — probe、frontend attach、exit、USB 属性
│   ├── lme2511.h            # 常量、结构体、BUILD_ID、公开 API 声明
│   ├── lme2511_fw.c         # 冷/暖状态检测 + 固件上传
│   ├── lme2511_i2c.c        # EP1 Bulk I2C 桥（dvb-usb-v2 算法）
│   ├── lme2511_mcu.c        # MCU 命令（流控制、PID 过滤、demod 变体选择）
│   ├── lgs8gl5.c            # LGS8GL5 DTMB 解调器驱动
│   ├── lgs8gl5.h            # LGS8GL5 寄存器表及初始化表
│   ├── max2165.c            # MAX2165 硅调谐器 — PLL、ROM 校准、初始化
│   ├── max2165.h            # MAX2165 配置结构体
│   ├── lme2511_status.c     # EP 0x8A 状态轮询 + frontend ops 重写
│   └── dvb_usb.h            # dvb-usb-v2 私有头文件（linux-headers 未导出）
├── firmware/                # 固件 blob（厂商提供）
│   ├── rom.dat              # MCU ROM 固件 (512 B)
│   └── fw_new.bin           # MCU APP 固件 (4836 B)
├── test/                    # 测试工具
│   ├── dvb_cap.c            # 简易 TS 录制测试工具
│   └── test_demux.c         # Demux 过滤测试工具
├── captures/                # 抓包资料
├── tools/                   # 分析脚本
├── Makefile                 # 外部模块构建脚本
├── README.md
├── LICENSE
└── .gitignore
```

## 参考资料

本项目的开发资料保存在仓库内：

- `captures/` — 抓包日志与配套客户端二进制
- `tools/` — 分析脚本（反汇编、交叉引用、抓包解析），见 `tools/README.md`

## 许可证

GPL-2.0-only — 详见各源文件头。

## 免责声明

本驱动代码基于对配套客户端 USB 通信的抓包逆向；固件文件为芯片厂商
(LME/Legend) 的固件 blob（与配套客户端内嵌固件、内核 lmedm04 驱动所用固件
逐字节相同），仅供学习与研究目的。代码完全开源，**不得用于商业目的**。
作者对使用本驱动产生的任何后果不承担责任。

