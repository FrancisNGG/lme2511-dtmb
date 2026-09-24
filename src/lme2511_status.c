// SPDX-License-Identifier: GPL-2.0-only
/*
 * lme2511_status.c — EP8A interrupt status polling for LME2511 DTMB driver
 * Copyright (C) 2026 FrancisNGG
 *
 * EP8A (endpoint 0x8A) sends a 7-byte status packet every ~500ms:
 *   [0] = 0xBB  magic
 *   [1] = 0x05  (ignored)
 *   [2] = lock  (0=unlocked, 1=locked)
 *   [3] = agc   (signal strength low)
 *   [4] = snr   (SNR / FEC quality)
 *   [5] = str_hi (signal strength high)
 *   [6] = reserved
 *
 * These override the lgs8gl5 I2C-based read_status/signal/snr
 * with EP8A-interrupt-based implementations.
 */

#include "lme2511.h"

#include <linux/usb.h>
#include <media/dvb_frontend.h>

/* ── Interrupt URB callback ────────────────────────────────────── */

static void lme2511_int_callback(struct urb *urb)
{
	struct dvb_usb_adapter *adap = urb->context;
	struct dvb_usb_device *d = adap_to_d(adap);
	struct lme2511_state *st = d->priv;
	u8 *buf;

	printk(KERN_INFO "lme2511: EP8A callback status=%d len=%d\n",
	       urb->status, urb->actual_length);

	switch (urb->status) {
	case 0:
	case -ETIMEDOUT:
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		return;
	default:
		dev_dbg(&d->udev->dev, "%s: urb error %d\n",
			__func__, urb->status);
		break;
	}

	buf = (u8 *)urb->transfer_buffer;

	if (urb->actual_length >= 8) {
		printk(KERN_INFO "lme2511: EP8A data: %02x %02x %02x %02x %02x %02x %02x %02x\n",
		       buf[0], buf[1], buf[2], buf[3],
		       buf[4], buf[5], buf[6], buf[7]);
	}

	if (urb->actual_length >= STATUS_PKT_LEN && buf[0] == STATUS_MAGIC) {
		st->signal_lock        = buf[2];
		st->signal_strength_lo = buf[3];   /* agc */
		st->signal_snr         = buf[4];
		st->signal_strength_hi = buf[5];
		dev_dbg(&d->udev->dev,
			"EP8A status: lock=%u agc=%u snr=%u str_hi=%u\n",
			buf[2], buf[3], buf[4], buf[5]);
	} else {
		dev_dbg(&d->udev->dev,
			"EP8A status: bad pkt len=%d magic=0x%02x\n",
			urb->actual_length, buf[0]);
	}

	/* Resubmit */
	{
		int rc = usb_submit_urb(urb, GFP_ATOMIC);
		if (rc < 0) {
			dev_err(&d->udev->dev,
				"EP8A resubmit failed: %d (status=%d)\n",
				rc, urb->status);
		}
	}
}

/* ── Interrupt URB init ────────────────────────────────────────── */

static int lme2511_int_start(struct dvb_usb_adapter *adap)
{
	struct dvb_usb_device *d = adap_to_d(adap);
	struct lme2511_state *st = d->priv;
	int ret;

	st->int_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!st->int_urb)
		return -ENOMEM;

	/* EP 0x8A may be reported as bulk on some controllers (EHCI quirk).
	 * Use interrupt fill; if the endpoint descriptor says bulk,
	 * override the pipe. */
	{
		struct usb_host_endpoint *ep;

		usb_fill_int_urb(st->int_urb, d->udev,
				 usb_rcvintpipe(d->udev, 0x8a),
				 st->int_buffer, sizeof(st->int_buffer),
				 lme2511_int_callback, adap, 11);

		ep = usb_pipe_endpoint(d->udev, st->int_urb->pipe);
		if (ep &&
		    usb_endpoint_type(&ep->desc) == USB_ENDPOINT_XFER_BULK) {
			st->int_urb->pipe =
				usb_rcvbulkpipe(d->udev, 0x8a);
		}
	}

	ret = usb_submit_urb(st->int_urb, GFP_KERNEL);
	if (ret) {
		usb_free_urb(st->int_urb);
		st->int_urb = NULL;
		return ret;
	}

	dev_info(&d->udev->dev, "EP8A interrupt URB started (pipe=0x%x)\n",
		 st->int_urb->pipe);
	return 0;
}

/* ── Frontend ops overrides ────────────────────────────────────── */

static struct lme2511_state *fe_to_lme2511(struct dvb_frontend *fe)
{
	struct dvb_usb_device *d = fe_to_d(fe);
	return d->priv;
}

int lme2511_read_status(struct dvb_frontend *fe, enum fe_status *status)
{
	struct lme2511_state *st = fe_to_lme2511(fe);

	*status = 0;

	if (st->signal_strength_hi || st->signal_strength_lo)
		*status |= FE_HAS_SIGNAL;

	if (st->signal_lock)
		*status |= (FE_HAS_LOCK | FE_HAS_CARRIER | FE_HAS_SYNC |
			    FE_HAS_VITERBI | FE_HAS_SIGNAL);

	return 0;
}

int lme2511_read_signal_strength(struct dvb_frontend *fe, u16 *strength)
{
	struct lme2511_state *st = fe_to_lme2511(fe);

	*strength = ((u16)st->signal_strength_hi << 8) | st->signal_strength_lo;
	return 0;
}

int lme2511_read_snr(struct dvb_frontend *fe, u16 *snr)
{
	struct lme2511_state *st = fe_to_lme2511(fe);

	*snr = st->signal_snr;
	return 0;
}

/* ── Public entry point (called from frontend_attach) ──────────── */

/*
 * lme2511_status_init — start EP8A interrupt URB and override
 * frontend ops with EP8A-based implementations.
 *
 * Call this after frontend is attached.
 */
int lme2511_status_init(struct dvb_usb_adapter *adap)
{
	int ret = lme2511_int_start(adap);
	if (ret < 0)
		return ret;

	/* Override frontend ops: EP8A for signal/SNR, keep I2C for lock */
	if (adap->fe[0]) {
		adap->fe[0]->ops.read_signal_strength =
			lme2511_read_signal_strength;
		adap->fe[0]->ops.read_snr = lme2511_read_snr;
	}

	return 0;
}
