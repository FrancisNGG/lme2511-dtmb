/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * max2165.h — MAX2165 tuner config for LME2511 DTMB driver
 * Copyright (C) 2026 FrancisNGG
 */

#ifndef LME2511_MAX2165_H
#define LME2511_MAX2165_H

#include <linux/types.h>

struct max2165_config {
	/* Linux I2C 7-bit address (0x60 → wire 0xC0) */
	u8 i2c_address;
	u32 osc_clk_khz;         /* 12000 (12 MHz) */
	u32 default_freq_khz;    /* 474000 */
};

#endif /* LME2511_MAX2165_H */
