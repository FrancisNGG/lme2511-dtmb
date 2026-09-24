/*
 * dvb_cap.c — minimal DVB capture tool
 * Usage: dvb_cap <freq_hz> <duration_sec> <out_file>
 *
 * Flow: open frontend → open DVR (pre-allocate dvr_buffer) →
 *       set demux filter (triggers start_feed) → tune → wait lock → read DVR
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <linux/dvb/frontend.h>
#include <linux/dvb/dmx.h>

int main(int argc, char *argv[])
{
	if (argc < 4) {
		fprintf(stderr, "Usage: %s <freq_hz> <sec> <out.ts>\n", argv[0]);
		return 1;
	}
	unsigned int freq = atoi(argv[1]);
	int duration = atoi(argv[2]);
	const char *out_path = argv[3];

	/* 1. Open frontend */
	int fe = open("/dev/dvb/adapter0/frontend0", O_RDWR);
	if (fe < 0) { perror("open frontend"); return 1; }
	usleep(500000);  /* wait for frontend thread init */

	/* 2. Open DVR first — ensures dvr_buffer.data is valid
	 *    before any TS data arrives (kernel dmxdev allocates
	 *    dvr_buffer on first DVR open; until then writes are
	 *    silently dropped). */
	int dvr = open("/dev/dvb/adapter0/dvr0", O_RDONLY | O_NONBLOCK);
	if (dvr < 0) { perror("open dvr"); close(fe); return 1; }

	unsigned long buf_size = 256 * 1024;
	ioctl(dvr, DMX_SET_BUFFER_SIZE, buf_size);
	printf("DVR opened, buffer=%lu\n", buf_size);

	/* 3. Set demux pass-all filter (triggers start_feed → URBs submitted) */
	int dmx = open("/dev/dvb/adapter0/demux0", O_RDWR);
	if (dmx < 0) { perror("open demux"); close(dvr); close(fe); return 1; }

	struct dmx_pes_filter_params pes = {
		.pid      = 0x2000,
		.input    = DMX_IN_FRONTEND,
		.output   = DMX_OUT_TS_TAP,
		.pes_type = DMX_PES_OTHER,
		.flags    = DMX_IMMEDIATE_START,
	};
	if (ioctl(dmx, DMX_SET_PES_FILTER, &pes) < 0) {
		perror("DMX_SET_PES_FILTER"); close(dmx); close(dvr); close(fe); return 1;
	}
	printf("Demux filter set (pass-all)\n");

	/* 4. Tune */
	struct dtv_property props[4];
	struct dtv_properties dtv_props = { .num = 4, .props = props };
	props[0].cmd = DTV_CLEAR;
	props[1].cmd = DTV_FREQUENCY;      props[1].u.data = freq;
	props[2].cmd = DTV_BANDWIDTH_HZ;   props[2].u.data = 8000000;
	props[3].cmd = DTV_TUNE;

	if (ioctl(fe, FE_SET_PROPERTY, &dtv_props) < 0) {
		perror("FE_SET_PROPERTY"); close(dmx); close(dvr); close(fe); return 1;
	}
	printf("Tuned to %u Hz\n", freq);

	/* Wait for lock */
	printf("Waiting for lock...\n");
	fe_status_t status = 0;
	for (int i = 0; i < 50; i++) {
		usleep(200000);
		if (ioctl(fe, FE_READ_STATUS, &status) < 0) continue;
		if (status & FE_HAS_LOCK) {
			printf("LOCKED (0x%02x) after %d ms\n", status, (i+1)*200);
			break;
		}
		if (i % 5 == 4) printf("  status=0x%02x\n", status);
	}
	if (!(status & FE_HAS_LOCK))
		printf("Lock timeout, recording anyway\n");

	/* 5. Read from DVR */
	FILE *out = fopen(out_path, "wb");
	if (!out) { perror("fopen"); close(dvr); close(dmx); close(fe); return 1; }

	printf("Recording for %d seconds...\n", duration);
	unsigned char buf[188 * 100];
	unsigned long long total = 0;
	time_t deadline = time(NULL) + duration;
	struct timeval t0, tnow;
	gettimeofday(&t0, NULL);

	while (time(NULL) < deadline) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(dvr, &fds);
		struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
		int r = select(dvr + 1, &fds, NULL, NULL, &tv);
		if (r < 0) { perror("select"); break; }
		if (r == 0) { printf("."); fflush(stdout); continue; }
		int n = read(dvr, buf, sizeof(buf));
		gettimeofday(&tnow, NULL);
		double ts = (tnow.tv_sec - t0.tv_sec) + (tnow.tv_usec - t0.tv_usec) / 1e6;
		if (n < 0) { printf("\n[%.3f] read err: %s\n", ts, strerror(errno)); break; }
		if (n == 0) { printf("\n[%.3f] EOF\n", ts); break; }
		printf("\n[%.3f] READ %d bytes (total=%llu)\n", ts, n, total + n);
		fwrite(buf, 1, n, out);
		total += n;
	}
	fclose(out);
	printf("\nDone: %llu bytes (%llu pkts) written to %s\n",
	       total, total / 188, out_path);

	close(dvr);
	close(dmx);
	close(fe);
	return 0;
}
