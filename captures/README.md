# 抓包资料

本目录保存开发过程中采集的抓包日志与参考对象，用于复现与核对。

## 内容

| 文件 | 说明 |
|---|---|
| `usbmon_boot.log` | 设备初始化(boot)阶段的 usbmon 抓包（固件上传 + 启动 I2C 序列） |
| `usbmon_startup.log` | 启动初始化阶段的 usbmon 抓包 |
| `usbmon_522.log` | 522MHz 调谐锁定的 usbmon 抓包 |
| `reference_client.so` | 配套客户端二进制（研究对象） |

## 版权说明

- `reference_client.so` 是配套客户端的二进制，版权归其作者。此处仅作为研究对象保留，**不属于本项目的代码，也不随本项目重新分发**。
- usbmon 日志是 USB 总线通信的客观记录。
