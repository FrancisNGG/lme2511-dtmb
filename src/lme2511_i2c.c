// SPDX-License-Identifier: GPL-2.0-only
/*
 * lme2511_i2c.c -- I2C bridge via EP1 Bulk for LME2511 DTMB USB dongle
 * Copyright (C) 2026 FrancisNGG
 *
 * Wire format matches lme2511-cli golden reference.
 * All DMA buffers are kmalloc'd to avoid stack-DMA warnings.
 */
#include "lme2511.h"
#include <linux/i2c.h>
#include <linux/usb.h>
#include <linux/delay.h>
#include <linux/slab.h>

static int ep1_i2c_write(struct dvb_usb_device *d, bool is_tuner,
			 u8 waddr, const u8 *buf, int len)
{
	u8 *obuf;
	u8 *ack;
	int wlen, ret, actual;

	obuf = kmalloc(64, GFP_KERNEL);
	ack = kmalloc(8, GFP_KERNEL);
	if (!obuf || !ack) {
		kfree(obuf);
		kfree(ack);
		return -ENOMEM;
	}

	if (is_tuner) {
		obuf[0] = I2C_OP_WR_MULTI;
		obuf[1] = (u8)(len + 1);
		obuf[2] = waddr;
		memcpy(&obuf[3], buf, len);
		wlen = 3 + len;
	} else {
		if (len < 2) { kfree(obuf); kfree(ack); return -EINVAL; }
		obuf[0] = I2C_OP_WR_SINGLE;
		obuf[1] = 0x04;
		obuf[2] = waddr;
		obuf[3] = buf[0];
		obuf[4] = buf[1];
		wlen = 5;
	}

	mutex_lock(&d->usb_mutex);
	ret = usb_bulk_msg(d->udev, usb_sndbulkpipe(d->udev, EP_BULK_OUT),
			   obuf, wlen, &actual, 400);
	if (ret == 0)
		usb_bulk_msg(d->udev, usb_rcvbulkpipe(d->udev, EP_BULK_IN),
			     ack, 4, &actual, 1500);
	mutex_unlock(&d->usb_mutex);

	printk(KERN_INFO "lme2511_i2c WR is_tuner=%d op=%02x len=%d -> ack_actual=%d ack=%02x %02x %02x %02x\n",
	       is_tuner, obuf[0], wlen, actual, ack[0], ack[1], ack[2], ack[3]);
	if (wlen >= 5)
		printk(KERN_INFO "lme2511_i2c WR obuf[3..]=%02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
		       obuf[3], obuf[4], obuf[5], obuf[6], obuf[7], obuf[8],
		       obuf[9], obuf[10], obuf[11]);

	kfree(obuf);
	kfree(ack);
	return ret;
}

static int ep1_i2c_read(struct dvb_usb_device *d, bool is_tuner,
			u8 waddr, u8 reg, u8 *dest, int dlen)
{
	u8 *obuf;
	u8 *ibuf;
	int ret, actual;

	obuf = kmalloc(8, GFP_KERNEL);
	ibuf = kmalloc(4, GFP_KERNEL);
	if (!obuf || !ibuf) {
		kfree(obuf);
		kfree(ibuf);
		return -ENOMEM;
	}

	if (is_tuner) {
		obuf[0] = I2C_OP_RD_TUNER;
		obuf[1] = 0x03;
		obuf[2] = waddr;
		obuf[3] = reg;
		obuf[4] = 0x01;   /* app 逆向确认 tuner 读 byte[4]=0x01 */
	} else {
		obuf[0] = I2C_OP_RD_DEMOD;
		obuf[1] = 0x02;
		obuf[2] = waddr;
		obuf[3] = reg;
		/* app 读请求 byte[4] 按寄存器映射 (usbmon 抓包 2026-09-23):
		 *   0x4b/0xa4 → 0x1c;  0x07/0x03 → 0x60;
		 *   0xc5/0x04/0x37 → 0x01;  其他 → 0x00 */
		if (reg == 0x4b || reg == 0xa4)
			obuf[4] = 0x1c;
		else if (reg == 0x07 || reg == 0x03)
			obuf[4] = 0x60;
		else if (reg == 0xc5 || reg == 0x04 || reg == 0x37)
			obuf[4] = 0x01;
		else
			obuf[4] = 0x00;
	}

	mutex_lock(&d->usb_mutex);

	/* app 读函数 0x1264D0: OUT 写 5 字节消息 → IN 读 2 字节 (w4=2),
	 * 返回 byte[0]=ACK(0x55/0x88), byte[1]=数据 */
	ret = usb_bulk_msg(d->udev, usb_sndbulkpipe(d->udev, EP_BULK_OUT),
			   obuf, 5, &actual, 200);
	if (ret < 0)
		goto out;

	ret = usb_bulk_msg(d->udev, usb_rcvbulkpipe(d->udev, EP_BULK_IN),
			   ibuf, 2, &actual, 2000);

	printk(KERN_INFO "lme2511_i2c RD is_tuner=%d obuf=%02x %02x %02x %02x %02x -> ret=%d actual=%d ibuf=%02x %02x\n",
	       is_tuner, obuf[0], obuf[1], obuf[2], obuf[3], obuf[4], ret, actual,
	       ibuf[0], ibuf[1]);

	if (ret < 0 || actual < 2) {
		ret = (ret < 0) ? ret : -EAGAIN;
		goto out;
	}

	if (dlen > 0)
		dest[0] = ibuf[1];

out:
	mutex_unlock(&d->usb_mutex);
	kfree(obuf);
	kfree(ibuf);
	return ret;
}

/* EP0 写路径前向声明（定义在本文件后半部分） */
static int lme2511_ctrl_handshake(struct dvb_usb_device *d);
static int lme2511_ep0_write2(struct dvb_usb_device *d, u8 addr7, u8 b1, u8 b2);
static int lme2511_ep0_write_tuner_block(struct dvb_usb_device *d, const u8 *buf, int len);

static int lme2511_i2c_master_xfer(struct i2c_adapter *adap,
				struct i2c_msg msg[], int num)
{
	struct dvb_usb_device *d = i2c_get_adapdata(adap);
	struct lme2511_state *st = d->priv;
	int i, ret;

	mutex_lock(&d->i2c_mutex);

	for (i = 0; i < num; i++) {
		bool is_read = msg[i].flags & I2C_M_RD;
		u8 addr7 = msg[i].addr;
		bool is_tuner = (addr7 >= 0x40);
		u8 waddr = addr7 << 1;

		if (is_read) {
			u8 reg = is_tuner ? 0 : st->cached_demod_reg_addr;
			ret = ep1_i2c_read(d, is_tuner, waddr, reg,
					   msg[i].buf, msg[i].len);
		} else if (i + 1 < num && (msg[i + 1].flags & I2C_M_RD)) {
			u8 reg = msg[i].buf[0];
			ret = ep1_i2c_read(d, is_tuner, waddr, reg,
					   msg[i + 1].buf, msg[i + 1].len);
			i++;
		} else {
			if (!is_tuner && msg[i].len == 1) {
				st->cached_demod_reg_addr = msg[i].buf[0];
				ret = 0;
			} else {
				ret = ep1_i2c_write(d, is_tuner, waddr,
						    msg[i].buf, msg[i].len);
			}
		}

		if (ret < 0) {
			mutex_unlock(&d->i2c_mutex);
			return -EAGAIN;
		}
	}

	mutex_unlock(&d->i2c_mutex);
	return i;
}

/* 写 01=60 后读 07 同步（byte4=0x60，app 特有解锁步骤，恢复桥的 tuner 读） */
int lme2511_i2c_demod_sync(struct dvb_usb_device *d)
{
	u8 *obuf, *ibuf;
	int ret, actual;

	obuf = kmalloc(8, GFP_KERNEL);
	ibuf = kmalloc(4, GFP_KERNEL);
	if (!obuf || !ibuf) {
		kfree(obuf);
		kfree(ibuf);
		return -ENOMEM;
	}

	obuf[0] = I2C_OP_RD_DEMOD;
	obuf[1] = 0x02;
	obuf[2] = I2C_ADDR_DEMOD_PRIMARY << 1;
	obuf[3] = 0x07;
	obuf[4] = 0x60;

	mutex_lock(&d->usb_mutex);
	ret = usb_bulk_msg(d->udev, usb_sndbulkpipe(d->udev, EP_BULK_OUT),
			   obuf, 5, &actual, 200);
	if (ret < 0)
		goto out;
	ret = usb_bulk_msg(d->udev, usb_rcvbulkpipe(d->udev, EP_BULK_IN),
			   ibuf, 2, &actual, 2000);
out:
	mutex_unlock(&d->usb_mutex);

	printk(KERN_INFO "lme2511_i2c SYNC obuf=%02x %02x %02x %02x %02x -> ret=%d actual=%d ibuf=%02x %02x\n",
	       obuf[0], obuf[1], obuf[2], obuf[3], obuf[4], ret, actual, ibuf[0], ibuf[1]);
	kfree(obuf);
	kfree(ibuf);
	return ret;
}

/* ── EP0 vendor control transfer（app 锁定流程协议） ──
 *
 * 配套客户端的 LGS8GL5 锁定流程走 EP0 vendor control transfer
 * (libusb_control_transfer)，不是 EP2/EP6 bulk。
 * 0x1cc87c 反汇编确认 libusb_transfer.endpoint=0x00(EP0)、type=CONTROL、
 * flags=0x02(FREE_BUFFER)；之前 "[8]=2 是 EP2 OUT" 是字节序误读。
 *
 * 协议(逆向 0x1291a0 写 / 0x1296b4 读 / 0x135684 高层写):
 *   写数据 reg=val:  ctrl(0x40,bReq=2,wIndex=addr<<1,data=[reg,val],len=2)
 *                     ctrl(0xC0,bReq=0,wIndex=5,data=&ack,len=1)
 *   写地址 [reg]:     ctrl(0x40,bReq=3,wIndex=addr<<1,data=[reg],len=1)
 *                     ctrl(0xC0,bReq=0,wIndex=5,data=&ack,len=1)
 *   读数据:           ctrl(0xC0,bReq=2,wIndex=addr<<1,data=&val,len=1)
 *                     ctrl(0xC0,bReq=0,wIndex=5,data=&ack,len=1)
 *
 * addr = 7bit I2C 地址（LGS=0x19 → wIndex=0x32）。
 */

/* 一次 EP0 vendor control transfer */
static int lme2511_ctrl_xfer(struct dvb_usb_device *d, u8 bmRequestType, u8 bRequest,
			  u16 wValue, u16 wIndex, u8 *data, u16 wLength)
{
	int ret;
	unsigned int pipe = (bmRequestType & 0x80) ?
		usb_rcvctrlpipe(d->udev, 0) : usb_sndctrlpipe(d->udev, 0);

	mutex_lock(&d->usb_mutex);
	ret = usb_control_msg(d->udev, pipe, bRequest, bmRequestType,
			      wValue, wIndex, data, wLength, 2000);
	mutex_unlock(&d->usb_mutex);
	return ret;
}

/* EP0 握手（app 0x128f84: ctrl(0x40,bReq=0,wValue=0,wIndex=6,[0x44],1)）。
 * 这是 EP0 vendor 通信的前置；缺了它 firmware 不响应后续 vendor 请求
 * （此前 EP0 vendor 全部 -110 超时的根因）。
 */
static int lme2511_ctrl_handshake(struct dvb_usb_device *d)
{
	u8 data = 0x44;
	int ret;

	mutex_lock(&d->usb_mutex);
	ret = usb_control_msg(d->udev, usb_sndctrlpipe(d->udev, 0),
			      0x00, 0x40, 0, 6, &data, 1, 2000);
	mutex_unlock(&d->usb_mutex);
	return ret;
}

/* EP0 写 [b1,b2] 到 addr7（app 0x1291a0/0x12962c, w5=1 → bReq=3） */
static int lme2511_ep0_write2(struct dvb_usb_device *d, u8 addr7, u8 b1, u8 b2)
{
	u8 buf[2] = { b1, b2 };
	return lme2511_ctrl_xfer(d, 0x40, 0x03, 0, (u16)(addr7 << 1), buf, 2);
}

/* demod（LGS8GL5 @0x19）写寄存器：握手 + ctrl(0x40,bReq=3,wIndex=0x32,[reg,val],2) */
int lme2511_ctrl_write(struct dvb_usb_device *d, u8 addr7, u8 reg, u8 val)
{
	int ret;

	ret = lme2511_ctrl_handshake(d);
	if (ret < 0)
		return ret;
	ret = lme2511_ep0_write2(d, addr7, reg, val);
	return ret < 0 ? ret : 0;
}

/* tuner（MAX2165 @0x60，经 alt 0x1b）写寄存器：
 * 握手 + 0x82设地址 + 0x83 + 0x84写数据 + 0x80提交（app 0x129c80 序列）
 */
static int lme2511_ep0_write_tuner_reg(struct dvb_usb_device *d, u8 reg, u8 val)
{
	int ret;

	ret = lme2511_ctrl_handshake(d);
	if (ret < 0)
		return ret;
	ret = lme2511_ep0_write2(d, I2C_ADDR_DEMOD_ALT, 0x82, reg);
	if (ret < 0)
		return ret;
	ret = lme2511_ep0_write2(d, I2C_ADDR_DEMOD_ALT, 0x83, 0x00);
	if (ret < 0)
		return ret;
	ret = lme2511_ep0_write2(d, I2C_ADDR_DEMOD_ALT, 0x84, val);
	if (ret < 0)
		return ret;
	return lme2511_ep0_write2(d, I2C_ADDR_DEMOD_ALT, 0x80, 0x00);
}

/* tuner 写块：buf = [reg, data0, data1, ...]，从 reg 起连续写 */
static int __maybe_unused lme2511_ep0_write_tuner_block(struct dvb_usb_device *d, const u8 *buf, int len)
{
	u8 reg = buf[0];
	int i, ret;

	for (i = 1; i < len; i++) {
		ret = lme2511_ep0_write_tuner_reg(d, reg + (i - 1), buf[i]);
		if (ret < 0)
			return ret;
	}
	return 0;
}

/* EP0 读（app 0x1296b4 w1!=1: ctrl(0xC0,bReq=2,..,addr<<1,&val,1) + ACK ctrl(0xC0,bReq=0,..,5,&ack,1)） */
int lme2511_ctrl_read(struct dvb_usb_device *d, u8 addr7, u8 reg, u8 *val)
{
	u8 ack;
	int ret;

	ret = lme2511_ctrl_handshake(d);
	if (ret < 0)
		return ret;
	ret = lme2511_ctrl_xfer(d, 0xC0, 0x02, 0, (u16)(addr7 << 1), val, 1);
	if (ret < 0)
		return ret;
	ret = lme2511_ctrl_xfer(d, 0xC0, 0x00, 0, 5, &ack, 1);
	return ret < 0 ? ret : 0;
}

static u32 lme2511_i2c_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_I2C;
}

const struct i2c_algorithm lme2511_i2c_algo = {
	.master_xfer   = lme2511_i2c_master_xfer,
	.functionality = lme2511_i2c_func,
};
