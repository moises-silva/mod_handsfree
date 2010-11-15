/* SCO test audio app */

#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include "ipc.h"

/* SCO connections work with 48 byte-sized frames only */
#define PCM_MTU 48

static int loop_read(int sock, char *buf, ssize_t len)
{
	int r;
	int ret = 0;

	while (len > 0) {
		r = read(sock, buf, len);
		if (r < 0 ) {
			return r;
		}
		if (!r) {
			break;
		}
		ret += r;
		buf += r;
		len -= r;
	}
	return ret;
}

static int loop_write(int sock, char *buf, ssize_t len)
{
	int r = 0;
	int ret = 0;
	while (len > 0) {
		r = write(sock, buf, len);
		if (r < 0) {
			return r;
		}
		if (!r) {
			break;
		}
		ret += r;
		buf += r;
		len -= r;
	}
	return ret;
}	

static int send_message(int servicefd, const bt_audio_msg_header_t *msg)
{
	ssize_t r;
	printf("Sending %s -> %s\n", bt_audio_strtype(msg->type), bt_audio_strname(msg->name));
	r = loop_write(servicefd, (char *)msg, msg->length);
	if (r < 0) {
		perror("write");
		return -1;
	}
	if (r != msg->length) {
		fprintf(stderr, "Only wrote %d bytes out of %d\n", r, msg->length);
		return -1;
	}
	return 0;
}

static int read_message(int svcsock, bt_audio_msg_header_t *msg, size_t max)
{
	ssize_t r = 0;
	size_t payloadlen = 0;
	char *payload = 0;

	printf("Trying to receive message from audio service\n");

	r = loop_read(svcsock, (char *)msg, sizeof(*msg));

	if (r < 0) {
		perror("read");
		return -1;
	}

	if (!r) {
		printf("Server closed the connection\n");
		return -1;
	}

	if (r != sizeof(*msg)) {
		fprintf(stderr, "read only %d out of %d bytes, discarding ...\n", r, sizeof(*msg));
		return -1;
	}

	if (msg->length > max) {
		fprintf(stderr, "Not enough room to fit %d bytes, only room for %d, discarding ...\n", r, max);
		return -1;
	}

	printf("Received %s <- %s of length %d ... reading payload ...\n", bt_audio_strtype(msg->type), bt_audio_strname(msg->name), msg->length);
	if (msg->length > sizeof(*msg)) {
		payloadlen = msg->length - sizeof(*msg);
		payload = ((char *)msg) + sizeof(*msg);
		r = loop_read(svcsock, payload, payloadlen);
		if (r < 0) {
			perror("read");
			return -1;
		}
		if (!r) {
			printf("Server closed the connection\n");
			return -1;
		}
		if (r != payloadlen) {
			fprintf(stderr, "read only %d out of %d payload bytes, discarding ...\n", r, sizeof(*msg));
			return -1;
		}
	}
	printf("Finished receiving %s <- %s of length %d\n", bt_audio_strtype(msg->type), bt_audio_strname(msg->name), msg->length);
	return 0;
}

static int print_caps(int servicefd, char *obj)
{
	uint16_t bytes_left;
	const codec_capabilities_t *codec;
	int r = 0;
	union {
		struct bt_get_capabilities_req req;
		struct bt_get_capabilities_rsp rsp;
		bt_audio_error_t error;
		uint8_t buf[BT_SUGGESTED_BUFFER_SIZE];
	} msg;

	memset(&msg, 0, sizeof(msg));

	msg.req.h.type = BT_REQUEST;
	msg.req.h.name = BT_GET_CAPABILITIES;
	msg.req.h.length = sizeof(msg.req);
	msg.req.seid = 0;

	//msg.req.flags = BT_FLAG_AUTOCONNECT;
	msg.req.flags = 0;

	snprintf(msg.req.object, sizeof(msg.req.object), "%s", obj);
	msg.req.transport = BT_CAPABILITIES_TRANSPORT_SCO;

	r = send_message(servicefd, &msg.req.h);
	if (r < 0) {
		return r;
	}

	r = read_message(servicefd, &msg.rsp.h, sizeof(msg));
	if (r < 0) {
		return r;
	}
	if (msg.rsp.h.type == BT_ERROR) {
		fprintf(stderr, "Failed to get capabilities\n");
		return -1;
	}

	bytes_left = msg.rsp.h.length - sizeof(msg.rsp);
	codec = (codec_capabilities_t *)msg.rsp.data;

	if (bytes_left < sizeof(*codec)) {
		fprintf(stderr, "%lu bytes are not enough to hold codec data of length %lu\n", 
				(unsigned long)bytes_left, (unsigned long)sizeof(*codec));
		return -1;
	}

	printf("Payload size is %lu %lu\n", (unsigned long)bytes_left, (unsigned long)sizeof(*codec));

	printf("Codec Seid: %d\n", codec->seid);
	printf("Codec Transport: %d\n", codec->transport);
	printf("Codec Type: %d\n", codec->type);
	printf("Codec Length: %d\n", codec->length);
	
	return 0;
}

static int open_device(int servicefd, char *obj)
{
	int r = 0;
	union {
		struct bt_open_req open_req;
		struct bt_open_rsp open_rsp;
		struct bt_set_configuration_req setconf_req;
		struct bt_set_configuration_rsp setconf_rsp;
		bt_audio_error_t error;
		uint8_t buf[BT_SUGGESTED_BUFFER_SIZE];
	} msg;

	/* now open the device */
	memset(&msg, 0, sizeof(msg));

	msg.open_req.h.type = BT_REQUEST;
	msg.open_req.h.name = BT_OPEN;
	msg.open_req.h.length = sizeof(msg.open_req);
	msg.open_req.seid = 0;

	snprintf(msg.open_req.object, sizeof(msg.open_req.object), "%s", obj);
	/* QUESTION: What is this SEID RANGE thing? */
	msg.open_req.seid = BT_A2DP_SEID_RANGE + 1;
	/* QUESTION: what are those 2 locks? */
	msg.open_req.lock = BT_READ_LOCK | BT_WRITE_LOCK;

	r = send_message(servicefd, &msg.open_req.h);
	if (r < 0) {
		return r;
	}

	r = read_message(servicefd, &msg.open_rsp.h, sizeof(msg));
	if (r < 0) {
		return r;
	}
	if (msg.open_rsp.h.type == BT_ERROR) {
		fprintf(stderr, "Failed to open device %s\n", obj);
		return -1;
	}

	/* at this point device is open. It seems for HFP we always have: LINEAR16, 1 channel at 8khz
	 * is time to configure ... 
	 */
	memset(&msg, 0, sizeof(msg));

	/* QUESTION: is the request configuration global? why no device is specified? */
	msg.setconf_req.h.type = BT_REQUEST;
	msg.setconf_req.h.name = BT_SET_CONFIGURATION;
	msg.setconf_req.h.length = sizeof(msg.setconf_req);

	msg.setconf_req.codec.transport = BT_CAPABILITIES_TRANSPORT_SCO;
	msg.setconf_req.codec.seid = BT_A2DP_SEID_RANGE + 1;
	msg.setconf_req.codec.length = sizeof(pcm_capabilities_t);
	msg.setconf_req.h.length += msg.setconf_req.codec.length - sizeof(msg.setconf_req.codec);

	r = send_message(servicefd, &msg.setconf_req.h);
	if (r < 0) {
		return r;
	}

	r = read_message(servicefd, &msg.setconf_rsp.h, sizeof(msg));
	if (r < 0) {
		return r;
	}
	if (msg.setconf_rsp.h.type == BT_ERROR) {
		fprintf(stderr, "Failed to configure device %s\n", obj);
		return -1;
	}

	printf("Device %s configured successfuly, MTU = %d\n", obj, msg.setconf_rsp.link_mtu);
	if (msg.setconf_rsp.link_mtu != PCM_MTU) {
		fprintf(stderr, "Unsupported MTU %d, we support %d\n", msg.setconf_rsp.link_mtu, PCM_MTU);
		return -1;
	}
	return 0;
}

static int close_device(int servicefd, char *obj)
{
	int r = 0;
	union {
		struct bt_close_req close_req;
		struct bt_close_rsp close_rsp;
		bt_audio_error_t error;
		uint8_t buf[BT_SUGGESTED_BUFFER_SIZE];
	} msg;

	/* now close the device */
	memset(&msg, 0, sizeof(msg));

	msg.close_req.h.type = BT_REQUEST;
	msg.close_req.h.name = BT_CLOSE;
	msg.close_req.h.length = sizeof(msg.close_req);

	r = send_message(servicefd, &msg.close_req.h);
	if (r < 0) {
		return r;
	}

	r = read_message(servicefd, &msg.close_rsp.h, sizeof(msg));
	if (r < 0) {
		return r;
	}
	if (msg.close_rsp.h.type == BT_ERROR) {
		fprintf(stderr, "Failed to close device %s\n", obj);
		return -1;
	}
	printf("Closed device %s\n", obj);
	return 0;
}

static int start_stream(int servicefd, char *obj)
{
	int pcmsock = -1;
	int f = 0;
	int r = 0;
#if 0
	int priority = 0;
	int one = 0;
#endif
	union {
		bt_audio_msg_header_t rsp;
		struct bt_start_stream_req start_req;
		struct bt_start_stream_rsp start_rsp;
		struct bt_new_stream_ind stream_ind;
		bt_audio_error_t error;
		uint8_t buf[BT_SUGGESTED_BUFFER_SIZE];
	} msg;

	/* start streaming! */
	memset(&msg, 0, sizeof(msg));

	msg.start_req.h.type = BT_REQUEST;
	msg.start_req.h.name = BT_START_STREAM;
	msg.start_req.h.length = sizeof(msg.start_req);

	r = send_message(servicefd, &msg.start_req.h);
	if (r < 0) {
		return r;
	}

	r = read_message(servicefd, &msg.start_rsp.h, sizeof(msg));	
	if (r < 0) {
		return r;
	}
	if (msg.start_rsp.h.type == BT_ERROR) {
		fprintf(stderr, "Failed to start streaming from device %s\n", obj);
		return -1;
	}

	r = read_message(servicefd, &msg.stream_ind.h, sizeof(msg));
	if (r < 0) {
		return r;
	}
	if (msg.stream_ind.h.type != BT_INDICATION 
	    || msg.stream_ind.h.name != BT_NEW_STREAM) {
		fprintf(stderr, "Stream indication error on device %s\n", obj);
		return -1;
	}

	pcmsock = bt_audio_service_get_data_fd(servicefd);
	if (pcmsock < 0) {
		fprintf(stderr, "Failed to retrieve pcm socket for device %s\n", obj);
		return pcmsock;
	}
	f = fcntl(pcmsock, F_GETFL);
	if (!(f & O_NONBLOCK)) {
		fcntl(pcmsock, F_SETFL, f | O_NONBLOCK);
	}
#if 0
	priority = 6;
	setsockopt(pcmsock, SOL_SOCKET, SO_PRIORITY, (void*)&priority, sizeof(priority));
	timestamp is used with recvmsg to get a timestamp of when the datagram was received
	one = 1;
	setsockopt(pcmsock, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one));
#endif
	printf("Got pcm socket %d!\n", pcmsock);
	return pcmsock;
}

static int stop_stream(int servicefd, char *obj)
{
	int r = 0;
	union {
		bt_audio_msg_header_t rsp;
		struct bt_start_stream_req start_req;
		struct bt_start_stream_rsp start_rsp;
		bt_audio_error_t error;
		uint8_t buf[BT_SUGGESTED_BUFFER_SIZE];
	} msg;

	/* start streaming! */
	memset(&msg, 0, sizeof(msg));

	msg.start_req.h.type = BT_REQUEST;
	msg.start_req.h.name = BT_STOP_STREAM;
	msg.start_req.h.length = sizeof(msg.start_req);

	r = send_message(servicefd, &msg.start_req.h);
	if (r < 0) {
		return r;
	}

	r = read_message(servicefd, &msg.start_rsp.h, sizeof(msg));	
	if (r < 0) {
		return r;
	}
	if (msg.start_rsp.h.type == BT_ERROR) {
		fprintf(stderr, "Failed to start streaming from device %s\n", obj);
		return -1;
	}
	printf("Stopped streaming from device %s\n", obj);
	return 0;
}

/*static const char digital_milliwatt[] = {0x1e,0x0b,0x0b,0x1e,0x9e,0x8b,0x8b,0x9e} ;*/
int main(int argc, char *argv[])
{
	union {
		bt_audio_msg_header_t h;
		bt_audio_error_t error;
		uint8_t buf[BT_SUGGESTED_BUFFER_SIZE];
	} msg;
	uint8_t pcmbuf[PCM_MTU];
	struct pollfd svcpoll[2];
	char *devname;
	int c = 0;
	int rc = 0;
	int audiostopped = 0;
	int svcsock = 0;
	int pcmsock = 0;
	int readcnt = 0;
	struct timespec lastrcv;
	struct timespec now;
	uint64_t lastrcv_us = 0;
	uint64_t now_us = 0;
	uint64_t avgus = 0;
	uint64_t maxus = 0;
	uint64_t minus = ULONG_MAX;
	uint64_t diffus = 0;

	if (argc < 2) {
		fprintf(stderr, "No device specified\n");
		return -1;
	}

	devname = argv[1];

	printf("Openning connection to %s for device %s\n", BT_IPC_SOCKET_NAME, devname);

	svcsock = bt_audio_service_open();

	if (svcsock < 0) {
		perror("audio service open failed");
		exit(1);
	}

	printf("Connected to the bluetooth audio service\n");
	if (print_caps(svcsock, devname)) {
		return -1;
	}

	if (open_device(svcsock, devname)) {
		return -1;
	}

start_streaming:	
	printf("Press 'q' to quit or any other key to start streaming\n");
	c = getchar();
	getchar();
	if (c == 'q') {
		printf("Quitting ...\n");
		goto done;
	}

	if ((pcmsock = start_stream(svcsock, devname)) < 0) {
		return -1;
	}

	printf("Audio socket is %d\n", pcmsock);

	svcpoll[0].fd = svcsock;
	svcpoll[0].events = POLLIN | POLLERR;
	svcpoll[1].fd = pcmsock;
	svcpoll[1].events = POLLIN | POLLERR;
	readcnt = 0;
	audiostopped = 0;
	memset(&lastrcv, 0, sizeof(lastrcv));
	memset(&now, 0, sizeof(now));
	for ( ; ; ) {

		svcpoll[0].revents = 0;
		svcpoll[1].revents = 0;

		rc = poll(svcpoll, 2, -1);
		if (rc < 0) {
			if (errno == EINTR) {
				break;
			}
			perror("poll failed");
			break;
		}

		if ((svcpoll[0].revents & POLLERR)) {
			fprintf(stderr, "POLLERR in service connection\n");
			break;
		}

		if ((svcpoll[1].revents & POLLERR)) {
			audiostopped = 1;
			close(pcmsock);
			pcmsock = -1;
			break;
		}

		if ((svcpoll[0].revents & POLLIN)) {
			rc = read_message(svcsock, &msg.h, sizeof(msg));
			if (rc < 0) {
				fprintf(stderr, "Failed to read service message\n");
				break;
			}
		}

		if ((svcpoll[1].revents & POLLIN)) {
			rc = read(pcmsock, pcmbuf, sizeof(pcmbuf));
			if (rc < 0) {
				perror("error reading from audio connection");
				break;
			}
			if (rc != sizeof(pcmbuf)) {
				fprintf(stderr, "Short read from audio connection (%d bytes)\n", rc);
			}
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (lastrcv.tv_sec) {
				now_us = ((now.tv_sec * 1000000) + (now.tv_nsec / 1000));
				lastrcv_us = ((lastrcv.tv_sec * 1000000) + (lastrcv.tv_nsec / 1000));
				diffus = now_us - lastrcv_us;
				if (diffus > maxus) {
					maxus = diffus;
				}
				if (diffus < minus) {
					minus = diffus;
				}
				avgus = (avgus + diffus) / 2;

			}
			memcpy(&lastrcv, &now, sizeof(lastrcv));
			readcnt++;
			rc = write(pcmsock, pcmbuf, rc);
			if (rc < 0) {
				perror("error writing to audio connection");
				break;
			}
			if (rc != sizeof(pcmbuf)) {
				fprintf(stderr, "Short write to audio connection (%d bytes)\n", rc);
			}
		}
	}

	stop_stream(svcsock, devname);

	printf("Stopping stream after %d bytes streamed, avgus = %llu, maxus = %llu, minus = %llu\n", 
			(readcnt * PCM_MTU), avgus, maxus, minus);

	if (audiostopped) {
		goto start_streaming;
	}

done:

	close_device(svcsock, devname);

	bt_audio_service_close(svcsock);

	exit(0);
}

