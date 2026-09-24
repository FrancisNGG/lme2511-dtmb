// SPDX-License-Identifier: GPL-2.0-only
/*
 * max2165.c — MAX2165 硅调谐器驱动 (第一波道 LME2511 + LGS8GL5 + MAX2165)
 * Copyright (C) 2026 FrancisNGG
 *
 * 基于对配套客户端 USB 通信的抓包(usbmon)逆向,
 * PLL/带宽/跟踪滤波写值均与 app 抓包逐字节一致。
 *
 *   - PLL: N_int + 20-bit frac  (FREF = 12 MHz fixed)
 *   - Bandwidth reg0A: ((ROM_8mhz - 2) << 4) | 0x03
 *   - Balun bypass: read reg4, write reg4 | 0xF0 (every tune)
 *   - Track filter: ntch select < 725 MHz, tf linear interpolation
 *   - ROM read via the lme2511 I2C adapter (uses EP1 Bulk internally)
 */

#include "lme2511.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <media/dvb_frontend.h>

/* ── Register map ──────────────────────────────────────────────── */
#define REG_NDIV_INT      0x00
#define REG_NDIV_FRAC2    0x01   /* upper nibble = frac[19:16], bit4=fractional on */
#define REG_NDIV_FRAC1    0x02   /* frac[15:8] */
#define REG_NDIV_FRAC0    0x03   /* frac[7:0] */
#define REG_TRACK_FILTER  0x04
#define REG_BASEBAND_CTRL 0x0A
#define REG_ROM_TABLE_ADDR 0x0D
#define REG_ROM_TABLE_DATA 0x10

#define MAX2165_OSC_KHZ   12000

struct max2165_priv {
	struct i2c_adapter *i2c;
	struct max2165_config cfg;  /* copy, not pointer */
	u32 frequency;
};

static int debug_max2165;
#define dprintk(args...) \
	do { if (debug_max2165) printk(KERN_DEBUG "max2165: " args); } while (0)

/* ── PLL calculation ───────────────────────────────────────────── */

static void max2165_pll_calc(u32 freq_khz, u8 *r0, u8 *r1, u8 *r2, u8 *r3)
{
	u32 n_int, rem;
	u64 frac_tmp;
	u32 frac20;

	n_int    = freq_khz / MAX2165_OSC_KHZ;
	rem      = freq_khz % MAX2165_OSC_KHZ;
	frac_tmp = (u64)rem << 20;
	frac20   = (u32)(frac_tmp / (u64)MAX2165_OSC_KHZ);

	*r0 = (u8)n_int;
	*r1 = 0x10 | (u8)((frac20 >> 16) & 0x0F);
	*r2 = (u8)((frac20 >> 8) & 0xFF);
	*r3 = (u8)(frac20 & 0xFF);
}

/* ── Track filter + bandwidth ──────────────────────────────────── */

static u8 max2165_track_filter(const struct lme2511_state *st, u32 freq_khz)
{
	u32 freq_mhz = freq_khz / 1000;
	u8 ntch;
	int delta, pos, tf;

	ntch = (freq_mhz < 725) ? st->rom_tf_ntch_low : st->rom_tf_ntch_hi;

	delta = (int)st->rom_tf_balun_hi - (int)st->rom_tf_balun_low;
	pos   = (int)freq_mhz - 470;
	if (pos < 0)   pos = 0;
	if (pos > 310) pos = 310;
	tf = (int)st->rom_tf_balun_low + (delta * pos) / 310;
	if (tf < 0)  tf = 0;
	if (tf > 15) tf = 15;

	return (ntch << 4) | (u8)tf;
}

static u8 max2165_bandwidth_reg(const struct lme2511_state *st)
{
	int adj = (int)st->rom_bb_8mhz - 2;
	if (adj < 0)  adj = 0;
	if (adj > 15) adj = 15;
	/* 低4位 = BB_BIA(bit3) | PD_TH[2:0](bit2-0). 实测 PD_TH=111 让 carrier 更差(不锁),
	 * 0x03(011) 让 carrier 一度锁, 故保留 0x03. 待确认 ROM[3] 低4位是否=0x03。 */
	return (u8)((adj << 4) | 0x03);
}

/* ── I2C helpers (use standard kernel I2C, routed via lme2511_i2c.c) ─ */

static int tuner_read_reg(struct dvb_usb_device *d, u8 reg, u8 *val)
{
	u8 r = reg;
	u8 v = 0;
	struct i2c_msg msgs[2] = {
		{ .addr = I2C_ADDR_TUNER, .flags = 0,       .buf = &r, .len = 1 },
		{ .addr = I2C_ADDR_TUNER, .flags = I2C_M_RD, .buf = &v, .len = 1 },
	};
	int ret = i2c_transfer(&d->i2c_adap, msgs, 2);
	if (ret != 2)
		return -EIO;
	*val = v;
	return 0;
}

/*
 * Write N registers starting at `reg` via a single i2c_msg.
 * buf_in contains [reg, data0, data1, ..., dataN−1].
 */
static int tuner_write_block(struct dvb_usb_device *d,
			     u8 *buf_in, int total_len)
{
	struct i2c_msg msg = { .addr = I2C_ADDR_TUNER, .flags = 0,
			       .buf = buf_in, .len = (u16)total_len };
	int ret = i2c_transfer(&d->i2c_adap, &msg, 1);
	if (ret != 1)
		return -EIO;
	return 0;
}

/* ── ROM calibration table read ────────────────────────────────── */

int max2165_read_rom(struct dvb_usb_device *d)
{
	struct lme2511_state *st = d->priv;
	u8 rom[6] = { 0 };
	int i;

	if (!st) {
		dev_err(&d->udev->dev, "%s: priv is NULL!\n", __func__);
		return -EINVAL;
	}

	for (i = 1; i <= 5; i++) {
		u8 idx = (u8)i;
		u8 buf[] = { REG_ROM_TABLE_ADDR, idx };

		/* Step 1: Set ROM table address */
		if (tuner_write_block(d, buf, sizeof(buf)) < 0)
			return -EIO;

		/* Step 2: Read ROM data */
		{
			u8 val;
			if (tuner_read_reg(d, REG_ROM_TABLE_DATA, &val) < 0)
				return -EIO;
			rom[i] = val;
		}
	}

	/* Exit ROM access mode: write reg 0x0D = 0 */
	{
		u8 buf[] = { REG_ROM_TABLE_ADDR, 0x00 };
		tuner_write_block(d, buf, sizeof(buf));
	}

	/* Decode ROM values */
	st->rom_tf_ntch_hi   = rom[1] & 0x0F;
	st->rom_tf_ntch_low  = rom[1] >> 4;
	st->rom_tf_balun_low = rom[2] & 0x0F;
	st->rom_tf_balun_hi  = rom[2] >> 4;
	st->rom_bb_8mhz      = rom[3] >> 4;

	dev_info(&d->udev->dev,
		 "MAX2165 ROM: ntch_low=0x%X ntch_hi=0x%X "
		 "balun_low=%d balun_hi=%d bb_8mhz=0x%X\n",
		 st->rom_tf_ntch_low, st->rom_tf_ntch_hi,
		 st->rom_tf_balun_low, st->rom_tf_balun_hi,
		 st->rom_bb_8mhz);

	return 0;
}

/* ── Full init (16-byte block, default 474 MHz) ────────────────── */

int max2165_init_tuner(struct dvb_usb_device *d)
{
	struct lme2511_state *st = d->priv;
	u8 r4, r10;
	u8 block[17];   /* reg + 16 data bytes */

	dev_dbg(&d->udev->dev, "MAX2165: full init (app 468MHz, frac off)\n");

	/* app 的 init block: 468MHz (N_int=39, frac=0), reg01=0x08 (fractional off) */
	r4  = max2165_track_filter(st, 468000) | 0xF0;
	r10 = max2165_bandwidth_reg(st);

	block[ 0] = 0x00;   /* starting register */
	block[ 1] = 0x27;   /* N_int=39 → 468MHz */
	block[ 2] = 0x18;   /* fractional ON(0x10) | F[19:16]=8 (app init 实际值, 非 0x08) */
	block[ 3] = 0x00;
	block[ 4] = 0x00;
	block[ 5] = r4;
	block[ 6] = 0x01;
	block[ 7] = 0x0A;
	block[ 8] = 0x08;
	block[ 9] = 0x02;
	block[10] = 0x54;   /* reg 0x09 VCO Control (app 用 0x54, 实测 0x50 会让 carrier 不锁) */
	block[11] = r10;
	block[12] = 0x75;
	block[13] = 0x00;
	block[14] = 0x00;
	block[15] = 0x00;
	block[16] = 0x00;

	if (tuner_write_block(d, block, sizeof(block)) < 0)
		return -EIO;

	/* 验证 init 写入 */
	{
		u8 r06, r07, r08, r09, r0b;
		int ok6 = tuner_read_reg(d, 0x06, &r06);
		int ok7 = tuner_read_reg(d, 0x07, &r07);
		int ok8 = tuner_read_reg(d, 0x08, &r08);
		int ok9 = tuner_read_reg(d, 0x09, &r09);
		int okb = tuner_read_reg(d, 0x0B, &r0b);
		printk(KERN_INFO "max2165: init readback(01=60前) reg06=0x%02x(ok%d) reg07=0x%02x(ok%d) reg08=0x%02x(ok%d) reg09=0x%02x(ok%d) reg0B=0x%02x(ok%d)\n",
		       r06, ok6, r07, ok7, r08, ok8, r09, ok9, r0b, okb);
	}

	dev_dbg(&d->udev->dev, "MAX2165: init done\n");
	return 0;
}

/* ── Short tune (set_params) ───────────────────────────────────── */

static int max2165_set_params(struct dvb_frontend *fe)
{
	struct dvb_usb_device *d = fe_to_d(fe);
	struct lme2511_state *st = d->priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	u32 freq_khz;
	u8 r0, r1, r2, r3, r4, r10;

	freq_khz = c->frequency / 1000;

	if (freq_khz < 470000 || freq_khz > 870000)
		return -EINVAL;

	dev_dbg(&d->udev->dev, "MAX2165: tune %u kHz (%u MHz)\n",
		freq_khz, freq_khz / 1000);

	/* 配套客户端 set_params 写序列 (照抄参考二进制 @0x126cb8):
	 * 1) 块写 reg 0x00-0x04 (PLL + track, r4 不含 0xF0)
	 * 2) 单写 reg 0x0A (bandwidth)
	 * 3) RMW reg 0x04 |= 0xF0 (balun bypass)
	 * 注意: set_params 阶段不重写 reg 0x05-0x09/0x0B-0x0F, 避免触发 autotuner 重扫 */
	max2165_pll_calc(freq_khz, &r0, &r1, &r2, &r3);
	r4 = max2165_track_filter(st, freq_khz);   /* 先不含 0xF0, RMW 时再加 */
	r10 = max2165_bandwidth_reg(st);
	printk(KERN_INFO "max2165: tune %u kHz pll=%02X %02X %02X %02X track=%02X bw=%02X\n",
	       freq_khz, r0, r1, r2, r3, r4, r10);

	/* 1) 块写 reg 0x00-0x04 */
	{
		u8 blk[6] = { 0x00, r0, r1, r2, r3, r4 };
		if (tuner_write_block(d, blk, sizeof(blk)) < 0)
			return -EIO;
	}

	/* 2) 单写 reg 0x0A */
	{
		u8 w10[] = { 0x0A, r10 };
		if (tuner_write_block(d, w10, sizeof(w10)) < 0)
			return -EIO;
	}

	/* 3) RMW reg 0x04 |= 0xF0 */
	{
		u8 v4;
		if (tuner_read_reg(d, 0x04, &v4) < 0)
			return -EIO;
		{
			u8 w4[] = { 0x04, (u8)(v4 | 0xF0) };
			if (tuner_write_block(d, w4, sizeof(w4)) < 0)
				return -EIO;
		}
	}

	/* 验证: 读回 reg 0x00 (N_int) + reg 0x04 (track filter) */
	{
		u8 r0_read, r4_read;
		int ok0 = tuner_read_reg(d, 0x00, &r0_read);
		int ok4 = tuner_read_reg(d, 0x04, &r4_read);
		printk(KERN_INFO "max2165: readback r0=0x%02x(ok%d) r4=0x%02x(ok%d)\n",
		       r0_read, ok0, r4_read, ok4);
	}

	return 0;
}

/* ── dvb_tuner_ops registration ────────────────────────────────── */

struct dvb_frontend *max2165_attach(struct dvb_frontend *fe,
					 struct i2c_adapter *i2c,
					 const struct max2165_config *cfg)
{
	struct max2165_priv *priv;

	dprintk("%s\n", __func__);

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (priv == NULL)
		return NULL;

	priv->i2c = i2c;
	priv->cfg = *cfg;

	/* Register only set_params — init and ROM read are handled
	 * separately during frontend_attach via max2165_init_tuner() */
	fe->ops.tuner_ops.set_params = max2165_set_params;
	fe->tuner_priv = priv;

	printk(KERN_INFO "max2165: MAX2165 tuner attached\n");
	return fe;
}
EXPORT_SYMBOL(max2165_attach);

module_param(debug_max2165, int, 0644);
MODULE_PARM_DESC(debug_max2165, "Turn on/off debugging (default:off).");

MODULE_DESCRIPTION("MAX2165 tuner driver");
MODULE_AUTHOR("LME2511 project");
MODULE_LICENSE("GPL");
