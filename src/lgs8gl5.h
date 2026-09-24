/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * lgs8gl5.h — LGS8GL5 demodulator config for LME2511 DTMB driver
 *
 * Copyright (C) 2026 FrancisNGG
 */

#ifndef LME2511_LGS8GL5_H
#define LME2511_LGS8GL5_H

#include <linux/types.h>

struct lgs8gl5_config {
	/* Linux I2C 7-bit addresses */
	u8 demod_address;        /* primary: 0x19 → wire 0x32 */
	u8 alt_address;          /* alternate: 0x1b → wire 0x36 */
};

#endif /* LME2511_LGS8GL5_H */
