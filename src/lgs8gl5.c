// SPDX-License-Identifier: GPL-2.0-only
/*
 * lgs8gl5.c — LGS-8GL5 DTMB 解调器驱动 (第一波道 LME2511 + LGS8GL5 + MAX2165)
 * Copyright (C) 2026 FrancisNGG
 *
 * 基于对配套客户端 USB 通信的抓包(usbmon)逐字节逆向实现。
 * 非官方/第三方驱动移植。
 *
 * 两条权威序列(均照抄 app 实测 usbmon 抓包):
 *   - 切台(set_frontend): 复位→unlock(01=e0)→tuner PLL→re-lock(01=60)→
 *     03=00→7e=01→alt c5=00→复位→04=02→37=01→复位→
 *     轮询 carrier(0x4b bit7)+FEC(0xa4&0x03==0x01)→收尾(7e=00→c5=06→复位→7d=A2→复位)
 *   - 启动初始化(lme2511_core.c attach): 复位→unlock→tuner ROM→tuner init(16B)→
 *     re-lock(01=60)→07=9f→09..0C=0→07=1c
 *
 * 关键点(实测):
 *   - FEC 锁定判定 = 0xA4 & 0x03 == 0x01 (bit0 lock), 不是 0x05(lock+sync)
 *   - re-lock 后写 0x38=0x51 (AGC 环使能), 弱信号频点靠它收敛 carrier 3→67
 */

#include "lme2511.h"
#include "lgs8gl5.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <media/dvb_frontend.h>
#include <media/dvb_demux.h>

/* ── Register map ─────────────────────────────────────────────── */
#define REG_CHIP_ID     0x00
#define REG_UNLOCK      0x01
#define REG_RESET       0x02
#define REG_03          0x03
#define REG_04          0x04
#define REG_37          0x37
#define REG_STRENGTH    0x4b
#define REG_STRENGTH_MASK       0x7f
#define REG_STRENGTH_CARRIER    0x80
#define REG_INVERSION   0x7c
#define REG_INVERSION_ON        0x80
#define REG_7D          0x7d
#define REG_7E          0x7e
#define REG_A2          0xa2
#define REG_STATUS      0xa4
#define REG_STATUS_LOCK 0x01
#define REG_AVG_NOISE   0x95
#define ALT_REG_C5      0xc5

/* BER 计数器 (app 反汇编 0x137b34): total = 0xd3..0xd0 大端,
 * errors = 0xd7..0xd4 大端; 0xc6 = 锁存控制(bit7)。 */
#define REG_BER_TOTAL0  0xd0
#define REG_BER_TOTAL3  0xd3
#define REG_BER_ERROR0  0xd4
#define REG_BER_ERROR3  0xd7
#define REG_BER_LATCH   0xc6

struct lgs8gl5_state {
	struct i2c_adapter *i2c;
	struct lgs8gl5_config config;  /* copy, not pointer */
	struct dvb_frontend frontend;
};

static int debug_lgs8gl5;
#define dprintk(args...) \
	do { \
		if (debug_lgs8gl5) \
			printk(KERN_DEBUG "lgs8gl5: " args); \
	} while (0)

/* ── I2C helpers ──────────────────────────────────────────────── */

static int lgs8gl5_write_reg(struct lgs8gl5_state *state,
				  u8 reg, u8 data)
{
	int ret;
	u8 buf[] = { reg, data };
	struct i2c_msg msg = {
		.addr  = state->config.demod_address,
		.flags = 0,
		.buf   = buf,
		.len   = 2
	};

	ret = i2c_transfer(state->i2c, &msg, 1);
	printk(KERN_INFO "lme2511_dbg: write reg 0x%02x = 0x%02x (ret=%d)\n", reg, data, ret);
	if (ret != 1)
		dprintk("%s: error (reg=0x%02x, val=0x%02x, ret=%i)\n",
			__func__, reg, data, ret);
	return (ret != 1) ? -1 : 0;
}

static int lgs8gl5_read_reg(struct lgs8gl5_state *state, u8 reg)
{
	int ret;
	u8 b0[] = { reg };
	u8 b1[] = { 0 };
	struct i2c_msg msg[2] = {
		{ .addr = state->config.demod_address, .flags = 0, .buf = b0, .len = 1 },
		{ .addr = state->config.demod_address, .flags = I2C_M_RD, .buf = b1, .len = 1 },
	};

	ret = i2c_transfer(state->i2c, msg, 2);
	if (ret != 2)
		return -EIO;
	printk(KERN_INFO "lme2511_dbg: read reg 0x%02x = 0x%02x\n", reg, b1[0]);
	return b1[0];
}

static int lgs8gl5_write_alt_reg(struct lgs8gl5_state *state,
				      u8 reg, u8 data)
{
	int ret;
	u8 buf[] = { reg, data };
	struct i2c_msg msg = {
		.addr  = state->config.alt_address,
		.flags = 0,
		.buf   = buf,
		.len   = 2
	};

	ret = i2c_transfer(state->i2c, &msg, 1);
	return (ret != 1) ? -1 : 0;
}

static int lgs8gl5_read_alt_reg(struct lgs8gl5_state *state, u8 reg)
{
	int ret;
	u8 b0[] = { reg };
	u8 b1[] = { 0 };
	struct i2c_msg msg[2] = {
		{ .addr = state->config.alt_address, .flags = 0, .buf = b0, .len = 1 },
		{ .addr = state->config.alt_address, .flags = I2C_M_RD, .buf = b1, .len = 1 },
	};

	ret = i2c_transfer(state->i2c, msg, 2);
	if (ret != 2)
		return -EIO;
	return b1[0];
}

/* ── Init ──────────────────────────────────────────────────────── */

/*
 * lgs8gl5_init — full demod init (lme2511 variant).
 *
 * Diff from kernel lgs8gl5_init:
 *   - reg7 = 0x1C (|= 0x0C then &= 0x7C), not 0x10.
 *   - reg9/0A/0B/0C = 0x00, not 0x0E/0xE5/0x35/0x30.
 *   - NO alt[0xC2] = 0x28.  (Deleted.)
 */
static int lgs8gl5_init(struct dvb_frontend *fe)
{
	struct lgs8gl5_state *state = fe->demodulator_priv;

	if (!state) {
		pr_err("lgs8gl5: init called with null state\n");
		return -EINVAL;
	}

	dprintk("%s\n", __func__);

	/* Init property cache with valid defaults so userspace
	 * (tvheadend etc.) doesn't try frequency 0 on first open. */
	fe->dtv_property_cache.frequency = 474000000;
	fe->dtv_property_cache.bandwidth_hz = 8000000;
	fe->dtv_property_cache.delivery_system = SYS_DVBT;
	fe->dtv_property_cache.modulation = QAM_64;
	fe->dtv_property_cache.inversion = INVERSION_AUTO;

	/* NOTE: demod init (01=E0→60→07=9F→09..0C=0 + MAX2165→01=1C) 已在
	 * lme2511_core.c frontend attach 一次性完成（照抄配套客户端一次性
	 * init 流程）。此处不再重复写寄存器，避免打乱 demod 已就绪状态。 */

	return 0;
}

/* ── set_frontend ─────────────────────────────────────────────── */

/*
 * lgs8gl5_set_frontend — tune to a new frequency.
 *
 * Diff from kernel:
 *   - Unlock demod[1]=0xE0 before tuner set_params
 *   - Re-lock demod[1]=0x60 after
 *   - Demod resync + soft_reset + wait_lock (3-mode retry)
 */
static void lgs8gl5_cache_signal(struct dvb_frontend *fe);

static int lgs8gl5_set_frontend(struct dvb_frontend *fe)
{
	struct dtv_frontend_properties *p = &fe->dtv_property_cache;
	struct lgs8gl5_state *state = fe->demodulator_priv;
	struct dvb_usb_device *d = fe_to_d(fe);
	struct lme2511_state *st = d->priv;
	int ret = -ETIMEDOUT;
	int n;
	u8 val, a2;

	dprintk("%s\n", __func__);

	if (p->bandwidth_hz != 8000000)
		return -EINVAL;

	/* Allow I2C during demod re-init */
	st->stream_active = false;

	/* ── app 切台序列 (usbmon 抓包 2026-09-23, 权威实测) ──
	 * 复位 → unlock(01=e0) → tuner PLL → re-lock(01=60)
	 * → demod 锁定(03=00 / 7e=01 / alt c5=00 / 复位 / 04=02 / 37=01 / 复位)
	 * → 轮询 carrier(0x4b&0x80) + FEC(0xa4&0x01)
	 * → 收尾(7e=00 / alt c5=06 / 复位 / 7d=A2值 / 复位)
	 *
	 * 关键: app 切台没有 demod_full_init(28对表)/carrier_config(载波频率)/
	 * lock_config(15步)/recapture(10轮)/wait_lock(3-mode)。之前 lme2511 抄了
	 * 那一整套, 干扰 demod 锁定, 导致 carrier 强度 3~25、FEC 0xa4 恒 0x00。 */

	/* 0. 启动初始化 demod 配置 (07=9f → 09..0C=0 → 07=1c) 已移回 attach,
	 *    在 re-lock(01=60) 之后立即写 (app 抓包顺序: re-lock → 07=9f →
	 *    09..0C=0 → 07=1c)。set_frontend 只做切台序列。 */

	/* 1. 复位 + unlock (app 复位前读 0x02=0x01, 官方 soft_reset 也是读-改-写) */
	{
		u8 p03 = (u8)lgs8gl5_read_reg(state, 0x03);
		int p02 = lgs8gl5_read_reg(state, 0x02);
		printk(KERN_INFO "lme2511_dbg: before-reset 02=%02x 03=%02x\n", p02, p03);
	}
	lgs8gl5_write_reg(state, REG_RESET, 0x00);
	msleep(2);  /* app 复位断言 02=00 到释放 02=01 间隔 ~2ms, 让 demod 完全复位 */
	lgs8gl5_write_reg(state, REG_RESET, 0x01);
	msleep(10);
	{
		u8 r03 = (u8)lgs8gl5_read_reg(state, 0x03);
		u8 r04 = (u8)lgs8gl5_read_reg(state, 0x04);
		printk(KERN_INFO "lme2511_dbg: after-reset 03=%02x 04=%02x\n", r03, r04);
	}
	/* 实验: 模拟 app 复位后默认值 03=0x01, 04=0x00 (lme2511 复位未重置到该状态) */
	lgs8gl5_write_reg(state, REG_UNLOCK, 0xE0);
	{
		u8 u01 = (u8)lgs8gl5_read_reg(state, 0x01);
		u8 u03 = (u8)lgs8gl5_read_reg(state, 0x03);
		printk(KERN_INFO "lme2511_dbg: after-unlock 01=%02x 03=%02x\n", u01, u03);
	}

	/* 2. tuner PLL (MAX2165 set_params) */
	if (fe->ops.tuner_ops.set_params) {
		fe->ops.tuner_ops.set_params(fe);
		if (fe->ops.i2c_gate_ctrl)
			fe->ops.i2c_gate_ctrl(fe, 0);
	}

	/* 3. re-lock */
	lgs8gl5_write_reg(state, REG_UNLOCK, 0x60);

	/* 3a. AGC 环使能 (0x38=0x51, app demod_full_init 关键写)。
	 *    弱信号频点(482/538/586/602)靠此激活 AGC 环收敛 carrier 强度 3→67,
	 *    否则 carrier 停在 0x83 无法帧同步(sync)。 */
	lgs8gl5_write_reg(state, 0x38, 0x51);

	/* 3b. 诊断: re-lock 后寄存器状态 (对比 app 首次锁定 re-lock 后) */
	{
		u8 a01 = (u8)lgs8gl5_read_reg(state, 0x01);
		u8 a03 = (u8)lgs8gl5_read_reg(state, 0x03);
		u8 a7e = (u8)lgs8gl5_read_reg(state, 0x7e);
		u8 ac5 = (u8)lgs8gl5_read_alt_reg(state, 0xc5);
		u8 a04 = (u8)lgs8gl5_read_reg(state, 0x04);
		u8 a37 = (u8)lgs8gl5_read_reg(state, 0x37);
		u8 a3e = (u8)lgs8gl5_read_reg(state, 0x3E);
		u8 a95 = (u8)lgs8gl5_read_reg(state, 0x95);
		printk(KERN_INFO "lme2511_dbg: post-relock regs 01=%02x 03=%02x 7e=%02x c5=%02x 04=%02x 37=%02x agc3e=%02x noise95=%02x\n",
		       a01, a03, a7e, ac5, a04, a37, a3e, a95);
	}

	/* 4. demod 锁定配置 (app 切台: 写 03=00 直接开始锁定, 无 03=01 前置) */
	lgs8gl5_write_reg(state, REG_03, 0x00);
	lgs8gl5_write_reg(state, REG_7E, 0x01);
	lgs8gl5_write_alt_reg(state, ALT_REG_C5, 0x00);
	lgs8gl5_write_reg(state, REG_RESET, 0x00);
	lgs8gl5_write_reg(state, REG_RESET, 0x01);
	lgs8gl5_write_reg(state, REG_04, 0x02);
	lgs8gl5_write_reg(state, REG_37, 0x01);
	lgs8gl5_write_reg(state, REG_RESET, 0x00);
	lgs8gl5_write_reg(state, REG_RESET, 0x01);

	/* 5. 轮询 carrier(0x4b bit7) + FEC(0xa4 bit0) */
	for (n = 0; n < 30; n++) {
		val = lgs8gl5_read_reg(state, REG_STRENGTH);
		if (val < 0)
			return val;
		if (val & REG_STRENGTH_CARRIER) {
			int f;
			for (f = 0; f < 15; f++) {
				u8 s = lgs8gl5_read_reg(state, REG_STATUS);
				/* app FEC 锁定 = 0xA4 & 0x03 == 0x01 (bit0 lock, bit1 恒0)。
				 * 抓包实测 app 在 FEC=0x01 即读 A2 锁定, 不是 0x05(lock+sync)。
				 * 弱信号下 sync(bit2) 周期性, 等 0x05 会永超时。 */
				if (s >= 0 && ((s & 0x03) == 0x01)) {
					ret = 0;
					break;
				}
				msleep(20);
			}
			if (ret == 0)
				break;
		}
		msleep(20);
	}

	/* 6. 锁定收尾 */
	if (ret == 0) {
		a2 = lgs8gl5_read_reg(state, REG_A2);
		lgs8gl5_write_reg(state, REG_7E, 0x00);
		lgs8gl5_write_alt_reg(state, ALT_REG_C5, 0x06);
		lgs8gl5_write_reg(state, REG_RESET, 0x00);
		lgs8gl5_write_reg(state, REG_RESET, 0x01);
		if (a2 >= 0)
			lgs8gl5_write_reg(state, REG_7D, (u8)a2);
		lgs8gl5_write_reg(state, REG_RESET, 0x00);
		lgs8gl5_write_reg(state, REG_RESET, 0x01);

		/* 锁定后缓存信号指标(0x4b/0x95), 供 streaming 时 read_* 在 I2C
		 * 禁止期间返回。收尾有复位, demod 需重新锁定稳定; 弱台(586)AGC
		 * 收敛慢, 连续调谐场景实测 200ms 不够(偶发读到未收敛的虚假高值
		 * 76% 或复位全 0), 加长到 500ms。 */
		msleep(500);
		lgs8gl5_cache_signal(fe);
	}

	if (ret == 0) {
		struct dvb_usb_adapter *adap = fe_to_adap(fe);
		struct dvb_demux_feed *feed;
		int feed_count = 0;

		/* Re-start stream after demod re-init (only if actually streaming) */
		if (st->streaming) {
			lme2511_mcu_stream_restart(d);
			st->stream_active = true;
		}

		list_for_each_entry(feed, &adap->demux.feed_list, list_head) {
			feed_count++;
			dev_dbg(&d->udev->dev,
				 "lme2511: post_start feed[%d] pid=0x%04x type=%d state=%d\n",
				 feed_count, feed->pid, feed->type,
				 feed->state);
		}
		dev_dbg(&d->udev->dev,
			"lme2511: post_start feeds=%d streaming=%d\n",
			feed_count, st->streaming);
	}

	return ret;
}

/* ── get_frontend ──────────────────────────────────────────────── */

static int lgs8gl5_get_frontend(struct dvb_frontend *fe,
				     struct dtv_frontend_properties *p)
{
	struct dvb_usb_device *d = fe_to_d(fe);
	struct lme2511_state *st = d->priv;

	p->bandwidth_hz = 8000000;

	if (st->stream_active) {
		dev_dbg(&d->udev->dev, "lme2511: get_frontend: cached\n");
		return 0;
	}

	{
		struct lgs8gl5_state *state = fe->demodulator_priv;
		int inv = lgs8gl5_read_reg(state, REG_INVERSION);

		if (inv >= 0)
			p->inversion = (inv & REG_INVERSION_ON) ?
				       INVERSION_ON : INVERSION_OFF;
	}

	p->code_rate_HP = FEC_1_2;
	p->code_rate_LP = FEC_7_8;
	p->guard_interval = GUARD_INTERVAL_1_32;
	p->transmission_mode = TRANSMISSION_MODE_2K;
	p->modulation = QAM_64;
	p->hierarchy = HIERARCHY_NONE;

	return 0;
}

/* ── get_tune_settings ─────────────────────────────────────────── */

static int lgs8gl5_get_tune_settings(struct dvb_frontend *fe,
					  struct dvb_frontend_tune_settings *fesettings)
{
	fesettings->min_delay_ms = 240;
	fesettings->step_size    = 0;
	fesettings->max_drift    = 0;
	return 0;
}

/* ── Read status / signal / snr (I2C fallback) ─────────────────── */

/*
 * These are kept as fallback.  The USB bridge layer (lme2511_status.c)
 * overrides these ops with EP8A interrupt-based implementations
 * during frontend_attach.
 */

static int lgs8gl5_read_status(struct dvb_frontend *fe,
				    enum fe_status *status)
{
	struct lgs8gl5_state *state = fe->demodulator_priv;
	struct dvb_usb_device *d = fe_to_d(fe);
	struct lme2511_state *st = d->priv;
	int level, flags;

	/* During TS streaming, avoid ALL EP1 I2C communication.
	 * MCU's USB-I2C bridge shares the bus with EP88 TS output;
	 * any I2C read during streaming causes MCU to stall TS.
	 * Use the EP8A status-packet cache instead (MCU pushes
	 * lock/AGC/SNR every ~500ms while streaming). */
	if (st->stream_active) {
		/* streaming 已启动 = set_frontend 已锁定(MCU 流 TS 中)。
		 * EP8A 中断端点未启用, signal_lock 不可靠; 直接报告完整锁定,
		 * 否则 dvbv5-zap 在流启动后因 read_status 归 0 而误判失锁。 */
		*status = FE_HAS_SIGNAL | FE_HAS_CARRIER |
			  FE_HAS_SYNC | FE_HAS_LOCK;
		return 0;
	}

	level = lgs8gl5_read_reg(state, REG_STRENGTH);
	flags = lgs8gl5_read_reg(state, REG_STATUS);

	if (level < 0 || flags < 0)
		return -EIO;

	*status = 0;
	printk(KERN_INFO "lme2511_dbg: read_status level=0x%02x flags=0x%02x\n", level, flags);

	if ((level & REG_STRENGTH_MASK) > 0)
		*status |= FE_HAS_SIGNAL;
	if (level & REG_STRENGTH_CARRIER)
		*status |= FE_HAS_CARRIER;
	/* app 语义: FEC lock(bit0) 即锁定, sync(bit2) 靠 TS 流启动后自动跟上。
	 * 弱信号频点(482) sync 周期性短暂出现(~80ms), 若坚持等 0x04 会错过锁定窗口,
	 * 导致 dvbv5-zap 永不判定 Lock(0x1b)。故 lock 即置 SYNC。 */
	if (flags & REG_STATUS_LOCK) {
		*status |= FE_HAS_LOCK;
		*status |= FE_HAS_SYNC;
	}

	return 0;
}

/* 读 0x4b 信号强度 / 0x95 C/N, 填充 st 缓存。
 * 锁定后调用, streaming 时 read_* 只能返回这些缓存值(I2C 禁止)。 */
static void lgs8gl5_cache_signal(struct dvb_frontend *fe)
{
	struct dvb_usb_device *d = fe_to_d(fe);
	struct lme2511_state *st = d->priv;
	struct lgs8gl5_state *state = fe->demodulator_priv;
	int level, noise;
	int samples[9];
	int i, j, k, tmp, r;

	level = lgs8gl5_read_reg(state, REG_STRENGTH);
	if (level >= 0)
		st->cached_signal_4b = (u16)((level & REG_STRENGTH_MASK) << 9);

	/* 0x95 是瞬时 AGC 噪声, 单次波动大(弱台实测 ±16%, 临界台可跳 0~77%)。
	 * 采样 9 次 × 50ms = 400ms 跨度取中位数, 覆盖 AGC 收敛过程。 */
	for (i = 0; i < 9; i++) {
		r = lgs8gl5_read_reg(state, REG_AVG_NOISE);
		if (r < 0)
			break;
		samples[i] = r & 0xff;
		if (i < 8)
			msleep(50);
	}
	if (i > 0) {
		for (j = 0; j < i - 1; j++)
			for (k = j + 1; k < i; k++)
				if (samples[k] < samples[j]) {
					tmp = samples[j];
					samples[j] = samples[k];
					samples[k] = tmp;
				}
		noise = samples[i / 2];  /* 中位数 */
		st->cached_snr = (u16)(noise << 8);
	}
}

/* 读 BER (app 协议 0x137b34): 0xc6/0xd0-d7 经 EP0 vendor control transfer
 * 访问 demod alt(0x1b)。先 0xc6 锁存(bit7) → 读 0xd0..0xd7 → 解除锁存。
 *   total  = 0xd3 d2 d1 d0 (d3 最高字节)
 *   errors = 0xd7 d6 d5 d4 (d7 最高字节)
 * EP0 vendor 在 streaming 时可用(app 播放时读 live status 实测), 与 TS 不冲突,
 * 故 read_ber 任何时候都直接读, 不走缓存。 */
static void __maybe_unused lgs8gl5_cache_ber(struct dvb_frontend *fe)
{
	struct dvb_usb_device *d = fe_to_d(fe);
	struct lme2511_state *st = d->priv;
	u8 c6 = 0, v[8] = {0};
	int i, ok = 1;

	if (lme2511_ctrl_read_reg(d, I2C_ADDR_DEMOD_ALT,
				  REG_BER_LATCH, &c6) >= 0)
		lme2511_ctrl_write_reg(d, I2C_ADDR_DEMOD_ALT,
				       REG_BER_LATCH, c6 | 0x80);

	for (i = 0; i < 8; i++) {
		if (lme2511_ctrl_read_reg(d, I2C_ADDR_DEMOD_ALT,
					  0xd0 + i, &v[i]) < 0) {
			ok = 0;
			break;
		}
	}

	lme2511_ctrl_write_reg(d, I2C_ADDR_DEMOD_ALT,
			       REG_BER_LATCH, c6 & 0x3f);

	if (ok) {
		u32 total = ((u32)v[3] << 24) | ((u32)v[2] << 16) |
			    ((u32)v[1] << 8) | v[0];
		u32 errors = ((u32)v[7] << 24) | ((u32)v[6] << 16) |
			     ((u32)v[5] << 8) | v[4];

		/* quality = 100 - errors*100/total; BER 以 ppm 表示 */
		if (total == 0 || errors > total)
			st->cached_ber = 0;
		else
			st->cached_ber = errors * 1000000 / total;

		printk(KERN_INFO
		       "lme2511_dbg: cache total=%u errors=%u ber=%u ppm\n",
		       total, errors, st->cached_ber);
	}
}

static int lgs8gl5_read_ber(struct dvb_frontend *fe, u32 *ber)
{
	/* BER 暂未实现, 返回 0。
	 *
	 * app 逆向结论 (reference_client.so 反汇编 0x137b34 + usbmon 抓包):
	 *   - BER 计数器 = demod alt(0x1b) 的 8 个寄存器 0xd0..0xd7:
	 *       total  = 0xd3 d2 d1 d0 (大端, d3 最高字节)
	 *       errors = 0xd7 d6 d5 d4 (大端, d7 最高字节)
	 *   - 读前先 0xc6 锁存(bit7=1), 读完 0xc6 解除(清 bit7+bit6)
	 *   - quality = 100 - errors*100/total (app 的 signal test 用)
	 *   - 走 EP1 bulk 命令(8 字节头 0x40/0xC0 + bReq + wValue + wIndex
	 *     + wLength), 不是 EP0 control, 也不是普通 I2C(0x85) —— 这是
	 *     app 读 0xc6/0xd0-d7 的专用协议, 尚未实现。
	 *   - 注意: app 播放时(live status)只读 0x4b/0x95/0xa4, 不读 BER;
	 *     0xd0-d7 仅 nativeTuneForSignalTest 功能用。
	 */
	*ber = 0;
	return 0;
}

static int lgs8gl5_read_signal_strength(struct dvb_frontend *fe,
				     u16 *signal_strength)
{
	struct dvb_usb_device *d = fe_to_d(fe);
	struct lme2511_state *st = d->priv;

	if (st->stream_active) {
		/* streaming: 频繁 I2C 读会 stall TS(app 播放时 I2C 读频率低
		 * 才不冲突), 用锁定后缓存的 0x4b */
		*signal_strength = st->cached_signal_4b;
		return 0;
	}

	{
		struct lgs8gl5_state *state = fe->demodulator_priv;
		int level = lgs8gl5_read_reg(state, REG_STRENGTH);

		if (level < 0)
			return -EIO;
		/* 信号强度 = 0x4B 低 7 位 <<9 (锁定态≈52%) */
		st->cached_signal_4b = (u16)((level & REG_STRENGTH_MASK) << 9);
		*signal_strength = st->cached_signal_4b;
	}
	return 0;
}

static int lgs8gl5_read_snr(struct dvb_frontend *fe, u16 *snr)
{
	struct dvb_usb_device *d = fe_to_d(fe);
	struct lme2511_state *st = d->priv;

	if (st->stream_active) {
		/* streaming: 用锁定后缓存的 0x95 */
		*snr = st->cached_snr;
		return 0;
	}

	{
		struct lgs8gl5_state *state = fe->demodulator_priv;
		int noise = lgs8gl5_read_reg(state, REG_AVG_NOISE);

		if (noise < 0)
			return noise;
		/* 0x95 = C/N 信号质量(越大越好) */
		st->cached_snr = (u16)((noise & 0xff) << 8);
		*snr = st->cached_snr;
	}
	return 0;
}

static int lgs8gl5_read_ucblocks(struct dvb_frontend *fe, u32 *ucblocks)
{
	*ucblocks = 0;
	return 0;
}

/* ── dvb_frontend_ops ──────────────────────────────────────────── */

static const struct dvb_frontend_ops lgs8gl5_ops;

/* ── attach ────────────────────────────────────────────────────── */

/*
 * lgs8gl5_attach — probe and create LGS8GL5 frontend.
 *
 * Diff from kernel lgs8gl5_attach:
 *   - Reads chip ID from demod[0x00], expects 0x0E (LGS8GL5).
 *   - Returns NULL if chip ID doesn't match.
 */
struct dvb_frontend *lgs8gl5_attach(
	const struct lgs8gl5_config *config,
	struct i2c_adapter *i2c)
{
	struct lgs8gl5_state *state = NULL;
	int chip_id;

	dprintk("%s\n", __func__);

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (state == NULL)
		goto error;

	state->config = *config;
	state->i2c    = i2c;

	/* Check if demod is there and chip ID = 0x0E */
	chip_id = lgs8gl5_read_reg(state, REG_CHIP_ID);
	if (chip_id < 0)
		goto error;

	dprintk("%s: chip_id = 0x%02X\n", __func__, chip_id);

	if (chip_id != 0x0E) {
		printk(KERN_ERR "lgs8gl5: unexpected chip ID 0x%02X "
		       "(expected 0x0E)\n", chip_id);
		goto error;
	}

	/* app @0x11979c demod_init: chip 检测后一次性跑 demod_full_init
	 * (28对表 + 0x24/0x31/0x38=0x51 AGC + 0x25 ADC 重启)。
	 * carrier_config 里的 demod_full_init 已改为频段门(同频段跳过),
	 * 故首次完整初始化在此完成。 */
	/* app 启动初始化不调 demod_full_init (usbmon 抓包 2026-09-23: 枚举后直接
	 * 复位→unlock→tuner init, 无 27 对表写)。demod_full_init 的 0x10~0x4d
	 * 写反而干扰, 故不调用。 */

	/* Create dvb_frontend */
	memcpy(&state->frontend.ops, &lgs8gl5_ops,
	       sizeof(struct dvb_frontend_ops));
	state->frontend.demodulator_priv = state;

	printk(KERN_INFO "lgs8gl5: LGS-8GL5 DMB-TH demod attached\n");
	return &state->frontend;

error:
	kfree(state);
	return NULL;
}
EXPORT_SYMBOL(lgs8gl5_attach);

/* ── dvb_frontend_ops instance ─────────────────────────────────── */

static const struct dvb_frontend_ops lgs8gl5_ops = {
	.delsys = { SYS_DVBT },
	.info = {
		.name            = "LGS-8GL5 DTMB",
		.frequency_min_hz  = 474 * MHz,
		.frequency_max_hz  = 858 * MHz,
		.frequency_stepsize_hz = 10 * kHz,
		.caps = FE_CAN_FEC_AUTO |
			FE_CAN_QPSK | FE_CAN_QAM_16 | FE_CAN_QAM_32 |
			FE_CAN_QAM_64 | FE_CAN_QAM_AUTO |
			FE_CAN_TRANSMISSION_MODE_AUTO |
			FE_CAN_BANDWIDTH_AUTO |
			FE_CAN_GUARD_INTERVAL_AUTO |
			FE_CAN_HIERARCHY_AUTO |
			FE_CAN_RECOVER
	},

	.release = NULL,  /* 不用 .release 释放 demod: 会触发 dvb_detach→symbol_put_addr
			   * 下溢同模块 refcnt。改由 props->frontend_detach 释放。 */

	.init = lgs8gl5_init,

	.set_frontend = lgs8gl5_set_frontend,
	.get_frontend = lgs8gl5_get_frontend,
	.get_tune_settings = lgs8gl5_get_tune_settings,

	.read_status = lgs8gl5_read_status,
	.read_ber = lgs8gl5_read_ber,
	.read_signal_strength = lgs8gl5_read_signal_strength,
	.read_snr = lgs8gl5_read_snr,
	.read_ucblocks = lgs8gl5_read_ucblocks,
};

module_param(debug_lgs8gl5, int, 0644);
MODULE_PARM_DESC(debug_lgs8gl5, "Turn on/off frontend debugging (default:off).");

MODULE_DESCRIPTION("LGS-8GL5 DTMB demodulator driver");
MODULE_AUTHOR("LME2511 project");
MODULE_LICENSE("GPL");
