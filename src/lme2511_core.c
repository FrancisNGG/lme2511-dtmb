// SPDX-License-Identifier: GPL-2.0-only
/*
 * lme2511_core.c — 第一波道 DTMB USB 电视棒 Linux DVB 驱动 (主模块)
 * Copyright (C) 2026 FrancisNGG
 *
 * Hardware: LME2511 + LGS8GL5 + MAX2165
 *
 * USB VID/PID: 0x3344/0x1120 (与内核自带 dvb_usb_lmedm04 共享 VID/PID, 须 blacklist)
 * 须 blacklist dvb_usb_lmedm04。
 *
 * Architecture:
 *   - dvb-usb-v2 framework (dvb_usbv2_probe / dvb_usbv2_disconnect)
 *   - EP1 Bulk I2C bridge  (lme2511_i2c.c)
 *   - MCU commands          (lme2511_mcu.c)
 *   - Firmware upload       (lme2511_fw.c)
 *   - LGS8GL5 demod         (lgs8gl5.c)
 *   - MAX2165 tuner         (max2165.c)
 *   - EP8A status polling   (lme2511_status.c)
 */

#include "lme2511.h"
#include "lgs8gl5.h"
#include "max2165.h"

#include <linux/module.h>
#include <linux/usb.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <media/dvb_demux.h>
#include "dvb_usb.h"

/* ── Power control ─────────────────────────────────────────────── */

int lme2511_power_ctrl(struct dvb_usb_device *d, int onoff)
{
	if (onoff) {
		int ret = usb_set_interface(d->udev,
					 d->props->bInterfaceNumber, 1);
		msleep(200);
		return ret;
	}
	return 0;
}

/* 释放 demod/tuner 私有内存。必须在 dvb_frontend_detach() 之前调用，
 * 因为 detach 会 free fe 容器（fe->demodulator_priv/tuner_priv 变成悬空）。
 * 原 .release 回调因 dvb_detach→symbol_put_addr 会下溢模块 refcnt 已移除，
 * 改在此处显式释放。 */
static void lme2511_frontend_free_state(struct dvb_frontend *fe)
{
	if (!fe)
		return;
	if (fe->demodulator_priv) {
		kfree(fe->demodulator_priv);
		fe->demodulator_priv = NULL;
	}
	if (fe->tuner_priv) {
		kfree(fe->tuner_priv);
		fe->tuner_priv = NULL;
	}
}

/* ── Frontend attach ───────────────────────────────────────────── */

int lme2511_frontend_attach(struct dvb_usb_adapter *adap)
{
	struct dvb_usb_device *d = adap_to_d(adap);
	const struct lgs8gl5_config demod_cfg = {
		.demod_address = I2C_ADDR_DEMOD_PRIMARY,
		.alt_address   = I2C_ADDR_DEMOD_ALT,
	};
	const struct max2165_config tuner_cfg = {
		.i2c_address      = I2C_ADDR_TUNER,
		.osc_clk_khz      = 12000,
		.default_freq_khz = 474000,
	};
	int ret;

	dev_dbg(&d->udev->dev, "%s\n", __func__);
	dev_info(&d->udev->dev, "BUILD_ID " BUILD_ID "\n");

	/* ── Chip detect: 读 demod[0x00] chip ID (app 实测 0x0E = LGS8GL5) ── */

	/* 1. Read chip ID from demod[0x00] (expect 0x0E = LGS8GL5) */

	adap->fe[0] = lgs8gl5_attach(&demod_cfg,
				 &d->i2c_adap);
	if (!adap->fe[0]) {
		dev_err(&d->udev->dev, "LGS8GL5 demod not found\n");
		return -ENODEV;
	}

	/* 2. MCU demod variant select {16 01 00} */
	ret = lme2511_mcu_demod_variant(d, 0x00);
	if (ret < 0) {
		dev_err(&d->udev->dev, "MCU demod variant select failed\n");
		lme2511_frontend_free_state(adap->fe[0]);
		dvb_frontend_detach(adap->fe[0]);
		adap->fe[0] = NULL;
		return ret;
	}

	/* 3. 复位 (app 启动初始化第一步: 02=00 → 02=01) */
	{
		u8 reg = 0x03, val = 0;
		struct i2c_msg msgs[2] = {
			{ .addr = I2C_ADDR_DEMOD_PRIMARY, .flags = 0,
			  .buf = &reg, .len = 1 },
			{ .addr = I2C_ADDR_DEMOD_PRIMARY, .flags = I2C_M_RD,
			  .buf = &val, .len = 1 },
		};
		if (i2c_transfer(&d->i2c_adap, msgs, 2) == 2)
			dev_info(&d->udev->dev, "attach: pre-reset 0x03=0x%02x\n", val);
	}
	{
		u8 buf[2];
		struct i2c_msg msg = { .addr = I2C_ADDR_DEMOD_PRIMARY,
				       .flags = 0, .buf = buf, .len = 2 };
		buf[0] = 0x02; buf[1] = 0x00;
		if (i2c_transfer(&d->i2c_adap, &msg, 1) != 1)
			goto demod_fail;
		msleep(2);  /* app 复位断言 02=00 到释放 02=01 间隔 ~2ms */
		buf[0] = 0x02; buf[1] = 0x01;
		if (i2c_transfer(&d->i2c_adap, &msg, 1) != 1)
			goto demod_fail;
		msleep(10);
	}

	/* 4. 01=E0 (unlock tuner 读路径 — ROM 校准/init 的必要前提) */
	{
		u8 buf[2];
		struct i2c_msg msg = { .addr = I2C_ADDR_DEMOD_PRIMARY,
				       .flags = 0, .buf = buf, .len = 2 };
		buf[0] = 0x01; buf[1] = 0xE0;
		if (i2c_transfer(&d->i2c_adap, &msg, 1) != 1)
			goto demod_fail;
	}

	/* 5. MAX2165 ROM 校准 + init (01=E0 后 tuner 可读) */
	msleep(50);
	ret = max2165_read_rom(d);
	if (ret < 0) {
		dev_err(&d->udev->dev, "MAX2165 ROM read failed\n");
		goto demod_fail;
	}

	ret = max2165_init_tuner(d);
	if (ret < 0) {
		dev_err(&d->udev->dev, "MAX2165 init failed\n");
		goto demod_fail;
	}

	/* 6. 01=60 (lock tuner 读路径 — 之后 tuner 读返回写缓存, 故须在 ROM/init 后) */
	{
		u8 buf[2];
		struct i2c_msg msg = { .addr = I2C_ADDR_DEMOD_PRIMARY,
				       .flags = 0, .buf = buf, .len = 2 };
		buf[0] = 0x01; buf[1] = 0x60;
		if (i2c_transfer(&d->i2c_adap, &msg, 1) != 1)
			goto demod_fail;
	}

	/* 6a. re-lock 后读 0x07 用 byte4=0x60 (app boot.log: 写 01=60 后读 07=0x93,
	 *     恢复桥的 tuner 读路径, 触发 demod 重同步) */
	lme2511_i2c_demod_sync(d);

	/* 7. 07=9f → 09..0C=0 → 07=1c (app 启动初始化: re-lock 之后立即写) */
	{
		u8 buf[2];
		struct i2c_msg msg = { .addr = I2C_ADDR_DEMOD_PRIMARY,
				       .flags = 0, .buf = buf, .len = 2 };
		buf[0] = 0x07; buf[1] = 0x9F;
		if (i2c_transfer(&d->i2c_adap, &msg, 1) != 1)
			goto demod_fail;
		buf[0] = 0x09; buf[1] = 0x00;
		if (i2c_transfer(&d->i2c_adap, &msg, 1) != 1)
			goto demod_fail;
		buf[0] = 0x0A; buf[1] = 0x00;
		if (i2c_transfer(&d->i2c_adap, &msg, 1) != 1)
			goto demod_fail;
		buf[0] = 0x0B; buf[1] = 0x00;
		if (i2c_transfer(&d->i2c_adap, &msg, 1) != 1)
			goto demod_fail;
		buf[0] = 0x0C; buf[1] = 0x00;
		if (i2c_transfer(&d->i2c_adap, &msg, 1) != 1)
			goto demod_fail;
		buf[0] = 0x07; buf[1] = 0x1C;
		if (i2c_transfer(&d->i2c_adap, &msg, 1) != 1)
			goto demod_fail;
	}

	/* 8. Attach tuner (registers set_params callback) */

	if (!max2165_attach(adap->fe[0], &d->i2c_adap, &tuner_cfg)) {
		dev_err(&d->udev->dev, "MAX2165 attach failed\n");
		goto demod_fail;
	}

	/* 9. Register I2C gate control (no-op — EP1 mutex in dvb-usb-v2) */
	adap->fe[0]->ops.i2c_gate_ctrl = lme2511_i2c_gate_ctrl;

	/* 10. Demod init (fe->ops.init) is deferred to frontend open.
	 *     The framework's dvb_usb_fe_init wrapper calls power_ctrl(1)
	 *     then our lgs8gl5_init — no need to call it here. */

	/* 11. EP8A interrupt URB disabled — MCU conflicts with TS streaming.
	 *     实验确认: 启用后中断端点每 ~512ms 返回 8B 状态, 但 FEC(0xa4)
	 *     仍恒 0x00 不锁 → 中断端点只是状态上报通道, 不影响锁定, 回退禁用 */
#if 0
	ret = lme2511_status_init(adap);
	if (ret < 0) {
		dev_err(&d->udev->dev, "EP8A interrupt init failed: %d\n",
			ret);
		goto demod_fail;
	}
#endif

	dev_info(&d->udev->dev, "LME2511 DTMB frontend ready\n");
	return 0;

demod_fail:
	if (adap->fe[0]) {
		lme2511_frontend_free_state(adap->fe[0]);
		dvb_frontend_detach(adap->fe[0]);
		adap->fe[0] = NULL;
	}
	return -ENODEV;
}

/* ── I2C gate control (no-op) ──────────────────────────────────── */

int lme2511_i2c_gate_ctrl(struct dvb_frontend *fe, int enable)
{
	/* All I2C operations share EP1 and are serialized by
	 * dvb-usb-v2's usb_mutex.  No additional gate needed. */
	return 0;
}

/* ── Streaming control ─────────────────────────────────────────── */

int lme2511_streaming_ctrl(struct dvb_frontend *fe, int onoff)
{
	struct dvb_usb_device *d = fe_to_d(fe);
	struct lme2511_state *st = d->priv;

	if (onoff) {
		struct dvb_usb_adapter *adap = fe_to_adap(fe);
		struct dvb_demux_feed *feed;
		int feed_count = 0;

		st->streaming = true;

		lme2511_mcu_set_pid_filter(d);
		lme2511_mcu_stream_restart(d);
		st->stream_active = true;

		list_for_each_entry(feed, &adap->demux.feed_list, list_head) {
			feed_count++;
			dev_info(&d->udev->dev,
				 "lme2511: feed[%d] pid=0x%04x type=%d state=%d\n",
				 feed_count, feed->pid, feed->type, feed->state);
		}
		dev_info(&d->udev->dev,
			 "lme2511: streaming_ctrl ON  feeds=%d streaming=%d\n",
			 feed_count, st->streaming);

		return 0;
	} else {
		st->streaming = false;
		st->stream_active = false;
		return 0;
	}
}

/* ── Stream config ─────────────────────────────────────────────── */

int lme2511_get_stream_config(struct dvb_frontend *fe, u8 *ts_type,
			   struct usb_data_stream_properties *stream)
{
	*ts_type = DVB_USB_FE_TS_TYPE_188;
	stream->endpoint = 0x88;
	return 0;
}

/* ── Exit ──────────────────────────────────────────────────────── */

void lme2511_exit(struct dvb_usb_device *d)
{
	struct lme2511_state *st = d->priv;
	int i, j;

	if (!st)
		return;

	if (st->int_urb) {
		usb_kill_urb(st->int_urb);
		usb_free_urb(st->int_urb);
		st->int_urb = NULL;
		dev_dbg(&d->udev->dev, "EP8A interrupt URB stopped\n");
	}

	/* 释放 demod/tuner 私有内存（原 .release 职责）。
	 * d->props->exit 在 dvb_usbv2_exit(detach fe) 之前调用，fe 仍有效。 */
	for (i = 0; i < MAX_NO_OF_ADAPTER_PER_DEVICE; i++)
		for (j = 0; j < MAX_NO_OF_FE_PER_ADAP; j++)
			lme2511_frontend_free_state(d->adapter[i].fe[j]);
}

/* ── dvb_usb_device_properties ─────────────────────────────────── */

static short adapter_nr[] = { 0, -1 };

static struct dvb_usb_device_properties lme2511_props = {
	.driver_name    = "lme2511",
	.owner          = THIS_MODULE,
	.adapter_nr     = adapter_nr,
	.bInterfaceNumber = 0,
	.size_of_priv   = sizeof(struct lme2511_state),

	.identify_state     = lme2511_identify_state,
	.download_firmware  = lme2511_download_firmware,

		.generic_bulk_ctrl_endpoint = 0x01,
		.generic_bulk_ctrl_endpoint_response = 0x01,

	.power_ctrl         = lme2511_power_ctrl,
	.i2c_algo           = &lme2511_i2c_algo,

	.frontend_attach    = lme2511_frontend_attach,
	.tuner_attach       = NULL,   /* done in frontend_attach */

	.streaming_ctrl     = lme2511_streaming_ctrl,
	.get_stream_config  = lme2511_get_stream_config,

	.exit               = lme2511_exit,

	.num_adapters = 1,
	.adapter = {
		{
			.stream =
			DVB_USB_STREAM_BULK(0x88, 10, 65536),
		},
	},
};

/* ── USB device ID table ───────────────────────────────────────── */

static const struct usb_device_id lme2511_id_table[] = {
	{
		DVB_USB_DEVICE(LME2511_VID, LME2511_PID_RUNTIME, &lme2511_props,
			       "LME2511 DTMB", RC_MAP_EMPTY)
	},
	{ }  /* terminating entry */
};

MODULE_DEVICE_TABLE(usb, lme2511_id_table);

/* ── USB driver ────────────────────────────────────────────────── */

static struct usb_driver lme2511_driver = {
	.name       = "lme2511",
	.probe      = dvb_usbv2_probe,
	.disconnect = dvb_usbv2_disconnect,
	.id_table   = lme2511_id_table,
};

module_usb_driver(lme2511_driver);

/* ── Module info ───────────────────────────────────────────────── */

MODULE_AUTHOR("LME2511 project");
MODULE_DESCRIPTION("LME2511 DTMB USB dongle DVB driver");
MODULE_VERSION("0.1.0");
MODULE_LICENSE("GPL");
MODULE_FIRMWARE(LME2511_FW_FILE);
