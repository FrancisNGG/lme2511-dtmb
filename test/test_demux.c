/*
 * test_demux.c — read TS from demux device directly (DMX_OUT_TSDEMUX_TAP)
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

int main(void)
{
	int fe, dmx, ret;
	unsigned char buf[188 * 100];
	unsigned long long total = 0;

	fe = open("/dev/dvb/adapter0/frontend0", O_RDWR);
	if (fe < 0) { perror("open fe"); return 1; }

	dmx = open("/dev/dvb/adapter0/demux0", O_RDWR | O_NONBLOCK);
	if (dmx < 0) { perror("open dmx"); return 1; }

	/* Set filter: pass-all, output to demux device */
	struct dmx_pes_filter_params pes = {
		.pid      = 0x2000,
		.input    = DMX_IN_FRONTEND,
		.output   = DMX_OUT_TSDEMUX_TAP,
		.pes_type = DMX_PES_OTHER,
		.flags    = DMX_IMMEDIATE_START,
	};
	if (ioctl(dmx, DMX_SET_PES_FILTER, &pes) < 0) {
		perror("DMX_SET_PES_FILTER"); return 1;
	}
	printf("filter set (DMX_OUT_TSDEMUX_TAP)\n");

	/* Set buffer size on demux device */
	unsigned long buf_size = 256 * 1024;
	ioctl(dmx, DMX_SET_BUFFER_SIZE, buf_size);

	/* Tune */
	struct dtv_property props[4];
	struct dtv_properties dtv_props = { .num = 4, .props = props };
	props[0].cmd = DTV_CLEAR;
	props[1].cmd = DTV_FREQUENCY;      props[1].u.data = 618000000;
	props[2].cmd = DTV_BANDWIDTH_HZ;   props[2].u.data = 8000000;
	props[3].cmd = DTV_TUNE;
	if (ioctl(fe, FE_SET_PROPERTY, &dtv_props) < 0) {
		perror("FE_SET_PROPERTY"); return 1;
	}
	printf("tuned\n");

	/* Wait lock */
	fe_status_t status = 0;
	for (int i = 0; i < 50; i++) {
		usleep(200000);
		ioctl(fe, FE_READ_STATUS, &status);
		if (status & FE_HAS_LOCK) {
			printf("LOCKED after %d ms\n", (i+1)*200);
			break;
		}
	}

	/* Read from demux device (not DVR!) for 5 seconds */
	printf("reading from demux0 for 5s...\n");
	time_t deadline = time(NULL) + 5;

	while (time(NULL) < deadline) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(dmx, &fds);
		struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
		ret = select(dmx + 1, &fds, NULL, NULL, &tv);
		if (ret < 0) { perror("select"); break; }
		if (ret == 0) { printf("."); fflush(stdout); continue; }
		int n = read(dmx, buf, sizeof(buf));
		if (n < 0) { perror("read"); break; }
		if (n == 0) break;
		printf("\nREAD %d bytes from demux0\n", n);
		/* Hex dump first 32 bytes of first read */
		if (total == 0) {
			printf("  hex: ");
			for (int i = 0; i < 32 && i < n; i++)
				printf("%02x ", buf[i]);
			printf("\n");
		}
		total += n;
	}

	printf("\nTotal: %llu bytes from demux0\n", total);
	close(dmx);
	close(fe);
	return 0;
}
