// SPDX-License-Identifier: GPL-2.0-only
/*
 * lme2511_mcu.c -- MCU commands for LME2511 DTMB USB dongle
 * Copyright (C) 2026 FrancisNGG
 */
#include "lme2511.h"
#include <linux/usb.h>
#include <linux/slab.h>
#include <linux/delay.h>

static int mcu_send(struct dvb_usb_device *d, const u8 *cmd, int cmdlen)
{
	u8 *buf;
	u8 *ack;
	int ret, actual;

	buf = kmalloc(cmdlen, GFP_KERNEL);
	ack = kmalloc(8, GFP_KERNEL);
	if (!buf || !ack) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(buf, cmd, cmdlen);

	mutex_lock(&d->usb_mutex);
	ret = usb_bulk_msg(d->udev, usb_sndbulkpipe(d->udev, EP_BULK_OUT),
			   buf, cmdlen, &actual, 200);
	if (ret == 0)
		usb_bulk_msg(d->udev, usb_rcvbulkpipe(d->udev, EP_BULK_IN),
			     ack, 8, &actual, 200);
	mutex_unlock(&d->usb_mutex);

out:
	kfree(buf);
	kfree(ack);
	return ret;
}

int lme2511_mcu_cmd(struct dvb_usb_device *d, u8 *buf, u8 len)
{
	return mcu_send(d, buf, len);
}

int lme2511_mcu_demod_variant(struct dvb_usb_device *d, u8 variant)
{
	u8 cmd[] = { MCU_OP_DEMOD_VARIANT, 0x01, variant };
	return lme2511_mcu_cmd(d, cmd, sizeof(cmd));
}

int lme2511_mcu_stream_start(struct dvb_usb_device *d)
{
	u8 all_pids[] = { 0x03, 0x06, 0x00, 0xff, 0x01, 0x1f, 0x20, 0x81 };
	u8 start[]    = { MCU_OP_STREAM_CTL, 0x00 };
	int ret;

	ret = mcu_send(d, all_pids, sizeof(all_pids));
	if (ret < 0)
		return -EIO;
	ret = mcu_send(d, all_pids, sizeof(all_pids));
	if (ret < 0)
		return -EIO;

	ret = mcu_send(d, start, sizeof(start));
	if (ret < 0)
		return -EIO;

	msleep(500);

	return 0;
}

int lme2511_mcu_stream_stop(struct dvb_usb_device *d)
{
	u8 cmd = MCU_OP_STREAM_STOP;

	mcu_send(d, &cmd, 1);

	return 0;
}

int lme2511_mcu_stream_restart(struct dvb_usb_device *d)
{
	u8 cmd = MCU_OP_STREAM_CTL;

	return mcu_send(d, &cmd, 1);
}

int lme2511_mcu_set_pid_filter(struct dvb_usb_device *d)
{
	u8 all_pids[] = { 0x03, 0x06, 0x00, 0xff, 0x01, 0x1f, 0x20, 0x81 };
	int ret;

	ret = mcu_send(d, all_pids, sizeof(all_pids));
	if (ret < 0)
		return ret;
	return mcu_send(d, all_pids, sizeof(all_pids));
}
