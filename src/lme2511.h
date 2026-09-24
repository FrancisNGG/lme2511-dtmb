/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * lme2511.h — LME2511 DTMB USB dongle Linux DVB driver
 *
 * Hardware: LME2511 + LGS8GL5 + MAX2165
 * Copyright (C) 2026 FrancisNGG
 */

#ifndef LME2511_H
#define LME2511_H

#define BUILD_ID "059"

#include <linux/types.h>
#include <linux/usb.h>
#include <linux/i2c.h>
#include "dvb_usb.h"
#include <media/dvb_frontend.h>

/* ── USB ──────────────────────────────────────────────────────── */

#define LME2511_VID                0x3344
#define LME2511_PID_RUNTIME        0x1120

/* ── Endpoints (alt-setting 1) ────────────────────────────────── */

#define EP_BULK_OUT             0x01
#define EP_BULK_IN              0x81
#define EP_TS_IN                0x88
#define EP_INTR_IN              0x8A

/* ── I2C addresses ────────────────────────────────────────────── */
/*
 * Linux I2C framework uses 7-bit addresses.
 * The lme2511 MCU expects raw 7-bit (demod) or 8-bit (tuner) on the wire.
 * master_xfer() converts internally.
 */
#define I2C_ADDR_DEMOD_PRIMARY  0x19    /* LGS8GL5 main, wire=0x32 */
#define I2C_ADDR_DEMOD_ALT      0x1b    /* LGS8GL5 alternate, wire=0x36 */
#define I2C_ADDR_TUNER          0x60    /* MAX2165, wire=0xC0 */

/* Wire addresses (used internally by lme2511_i2c.c) */
#define I2C_WIRE_DEMOD_PRIMARY  0x32
#define I2C_WIRE_DEMOD_ALT      0x36
#define I2C_WIRE_TUNER          0xc0

/* ── I2C opcodes (EP1 Bulk) ───────────────────────────────────── */

#define I2C_OP_WR_MULTI         0x04
#define I2C_OP_WR_SINGLE        0x05
#define I2C_OP_RD_TUNER         0x84
#define I2C_OP_RD_DEMOD         0x85

/* ── MCU opcodes ──────────────────────────────────────────────── */

#define MCU_OP_PID_FILTER       0x03
#define MCU_OP_STREAM_CTL       0x06
#define MCU_OP_STREAM_STOP      0x0a
#define MCU_OP_DEMOD_VARIANT    0x16

/* ── Firmware ─────────────────────────────────────────────────── */

#define FW_CHUNK_SIZE           50
#define FW_ROM_SIZE             512
#define FW_APP_SIZE             4836
#define FW_TOTAL_SIZE           (FW_ROM_SIZE + FW_APP_SIZE)  /* 5348 */
#define LME2511_FW_FILE            "dvb-usb-lme2511.fw"

/* ── Status packet ────────────────────────────────────────────── */

#define STATUS_MAGIC            0xbb
#define STATUS_PKT_LEN          7

/* ── Driver private state ─────────────────────────────────────── */

struct lme2511_state {
	/* EP8A interrupt transfer */
	struct urb *int_urb;
	u8 int_buffer[8];

	/* Cached EP8A status values */
	u8 signal_lock;
	u8 signal_strength_lo;   /* agc */
	u8 signal_snr;
	u8 signal_strength_hi;

	/* 0x4B signal-strength (REG_STRENGTH low 7 bits <<9), cached
	 * while streaming (I2C forbidden, EP8A carries no 0x4B). */
	u16 cached_signal_4b;

	/* MAX2165 ROM calibration table (read at init) */
	u8 rom_tf_ntch_hi;       /* rom[1] & 0x0F, freq >= 725 MHz */
	u8 rom_tf_ntch_low;      /* rom[1] >> 4,  freq <  725 MHz */
	u8 rom_tf_balun_low;     /* rom[2] & 0x0F, 470 MHz endpoint */
	u8 rom_tf_balun_hi;      /* rom[2] >> 4,  780 MHz endpoint */
	u8 rom_bb_8mhz;          /* rom[3] >> 4,  bb filter index */

	bool streaming;           /* feed active, URBs submitted */
	bool stream_active;        /* MCU TS streaming in progress —
				     * during this phase ALL EP1 (I2C/MCU)
				     * communication is forbidden to avoid
				     * USB bus contention with EP88 TS */

	/* TS sync: LME2511 MCU outputs TS with non-aligned boundaries.
	 * We scan for SYNC_DEPTH consecutive 0x47 at 188-byte stride
	 * before trusting packet alignment. */
	u8   ts_carry[564];       /* leftover bytes (max 3*188) */
	int  ts_carry_len;        /* bytes in carry buffer */
	bool ts_synced;           /* sync locked? */
	int  ts_resyncs;          /* resync counter */

	/* Cached demod register address for split reg-write/read I2C calls.
	 * The lme2511 MCU I2C bridge requires combined write-then-read on the wire;
	 * when the kernel I2C stack sends separate "write reg-addr" and "read"
	 * transactions, the reg is cached here and consumed by the next read.
	 */
	u8 cached_demod_reg_addr;
};

/* ── Sub-module headers (struct defs + public APIs) ───────────── */

#include "lgs8gl5.h"
#include "max2165.h"

/* ── Public API ───────────────────────────────────────────────── */

/* I2C */
extern const struct i2c_algorithm lme2511_i2c_algo;
int lme2511_i2c_demod_sync(struct dvb_usb_device *d);

/* Control-transfer I2C (app 锁定流程走 vendor control transfer, 非 bulk 桥消息) */
int lme2511_ctrl_write(struct dvb_usb_device *d, u8 addr7, u8 reg, u8 val);
int lme2511_ctrl_read(struct dvb_usb_device *d, u8 addr7, u8 reg, u8 *val);

/* MCU */
int lme2511_mcu_cmd(struct dvb_usb_device *d, u8 *buf, u8 len);
int lme2511_mcu_demod_variant(struct dvb_usb_device *d, u8 variant);
int lme2511_mcu_stream_start(struct dvb_usb_device *d);
int lme2511_mcu_stream_stop(struct dvb_usb_device *d);
int lme2511_mcu_stream_restart(struct dvb_usb_device *d);
int lme2511_mcu_set_pid_filter(struct dvb_usb_device *d);

/* Firmware */
int lme2511_identify_state(struct dvb_usb_device *d, const char **name);
int lme2511_download_firmware(struct dvb_usb_device *d,
			   const struct firmware *fw);

/* Power */
int lme2511_power_ctrl(struct dvb_usb_device *d, int onoff);

/* Frontend attach */
int lme2511_frontend_attach(struct dvb_usb_adapter *adap);

/* Streaming */
int lme2511_streaming_ctrl(struct dvb_frontend *fe, int onoff);

/* Status (EP8A interrupt URB + frontend ops override) */
int lme2511_status_init(struct dvb_usb_adapter *adap);
int lme2511_read_status(struct dvb_frontend *fe, enum fe_status *status);
int lme2511_read_signal_strength(struct dvb_frontend *fe, u16 *strength);
int lme2511_read_snr(struct dvb_frontend *fe, u16 *snr);

/* Stream config */
int lme2511_get_stream_config(struct dvb_frontend *fe, u8 *ts_type,
			   struct usb_data_stream_properties *stream);

/* Exit */
void lme2511_exit(struct dvb_usb_device *d);

/* I2C gate control (for DVB frontend) — no-op, EP1 mutex is in dvb-usb-v2 */
int lme2511_i2c_gate_ctrl(struct dvb_frontend *fe, int enable);

/* ── Demod ────────────────────────────────────────────────────── */

struct dvb_frontend *lgs8gl5_attach(
	const struct lgs8gl5_config *config,
	struct i2c_adapter *i2c);

/* ── Tuner ────────────────────────────────────────────────────── */

struct dvb_frontend *max2165_attach(
	struct dvb_frontend *fe,
	struct i2c_adapter *i2c,
	const struct max2165_config *cfg);

/*
 * Read MAX2165 ROM calibration table and store in lme2511_state.
 * Must be called with demod unlocked (demod[1] == 0xE0).
 */
int max2165_read_rom(struct dvb_usb_device *d);

/* Full tuner init (16-byte block, default frequency) */
int max2165_init_tuner(struct dvb_usb_device *d);

#endif /* LME2511_H */
