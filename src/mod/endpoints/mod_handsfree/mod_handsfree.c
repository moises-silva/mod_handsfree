/* 
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2010, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * This module (mod_handsfree) has been contributed by:
 *
 * Moises Silva (moises.silva@gmail.com)
 *
 * mod_handsfree.c -- Hands Free Profile Module
 *
 */
#include <switch.h>
#include <poll.h>
#include <sys/wait.h>
#include <poll.h>
#include <fcntl.h>
#include "ipc.h"


SWITCH_MODULE_LOAD_FUNCTION(mod_handsfree_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_handsfree_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_handsfree_runtime);
SWITCH_MODULE_DEFINITION(mod_handsfree, mod_handsfree_load, mod_handsfree_shutdown, mod_handsfree_runtime);

#define LIST_MODEMS_SCRIPT "list-modems"
#define LIST_DEVICES_SCRIPT "list-devices"
#define MONITOR_SCRIPT "monitor-ofono"
#define ANSWER_SCRIPT "answer"
#define HANGUP_SCRIPT "hangup"
#define DIAL_SCRIPT "dial-number"

#define EVENT_NAME_LEN 255
#define MODEM_NAME_LEN 255
#define MODEM_ID_LEN 255
#define CALL_NAME_LEN 255
#define EVENT_SRC_VOICE_CALL_MANAGER "{VoiceCallManager}"
#define EVENT_SRC_VOICE_CALL "{VoiceCall}"
#define EVENT_SRC_MODEM "{Modem}"
#define EVENT_SRC_CALL_VOL "{CallVolume}"
#define EVENT_SRC_NETWORK_REG "{NetworkRegistration}"

typedef enum {
	GFLAG_MY_CODEC_PREFS = (1 << 0)
} GFLAGS;

typedef enum {
	TFLAG_IO = (1 << 0),
	TFLAG_BREAK = (1 << 1),
	TFLAG_HANGUP = (1 << 2),
} TFLAGS;

typedef int (*script_consumer_cb_t)(char *line);
static char *get_modem_id_from_line(const char *line, char *modem_id, int modem_id_len);

switch_endpoint_interface_t *handsfree_endpoint_interface;

/* SCO connections work with 48 byte-sized frames only */
#define SCO_PCM_MTU 48

#define MODEM_RATE 8000
#define MODEM_INTERVAL 20
typedef struct ofono_modem {
	char id[MODEM_ID_LEN];
	char name[MODEM_NAME_LEN];
	char call_name[CALL_NAME_LEN];

	/* audio connection to bluez */
	int audiosock;

	uint8_t pcm_write_buf[SCO_PCM_MTU];
	int pcm_write_buf_len;
	uint64_t writecnt;

	uint8_t pcm_read_buf[SCO_PCM_MTU];
	int pcm_read_buf_len;
	uint64_t readcnt;

	unsigned char databuf[SWITCH_RECOMMENDED_BUFFER_SIZE];
	switch_core_session_t *session;
	switch_caller_profile_t *caller_profile;
	switch_mutex_t *mutex;

	switch_codec_t read_codec;
	switch_codec_t write_codec;
	switch_frame_t read_frame;

	int32_t flags;
	switch_mutex_t *flag_mutex;

	char dialplan[255];
	char context[255];

	uint8_t got_hangup;

	char bluez_path[512];
	int audio_service_fd;
	int audio_fd;

	uint8_t online;
	volatile uint8_t dialing;
	volatile uint8_t outgoing_ack;
} ofono_modem_t;

static struct {
	unsigned int flags;
	int calls;
	switch_mutex_t *mutex;
	volatile uint8_t running;
	volatile uint8_t thread_running;
	switch_hash_t *modems;
	switch_memory_pool_t *module_pool;
	char dialplan[255];
	char context[255];
	ofono_modem_t modems_array[50];
} globals;

static switch_status_t channel_on_init(switch_core_session_t *session);
static switch_status_t channel_on_hangup(switch_core_session_t *session);
static switch_status_t channel_on_destroy(switch_core_session_t *session);
static switch_status_t channel_on_routing(switch_core_session_t *session);
static switch_status_t channel_on_exchange_media(switch_core_session_t *session);
static switch_status_t channel_on_soft_execute(switch_core_session_t *session);
static switch_call_cause_t channel_outgoing_channel(switch_core_session_t *session, switch_event_t *var_event,
													switch_caller_profile_t *outbound_profile,
													switch_core_session_t **new_session, switch_memory_pool_t **pool, switch_originate_flag_t flags,
													switch_call_cause_t *cancel_cause);
static switch_status_t channel_read_frame(switch_core_session_t *session, switch_frame_t **frame, switch_io_flag_t flags, int stream_id);
static switch_status_t channel_write_frame(switch_core_session_t *session, switch_frame_t *frame, switch_io_flag_t flags, int stream_id);
static switch_status_t channel_kill_channel(switch_core_session_t *session, int sig);

static void execute_script(switch_stream_handle_t *stream, char *script, const char *arg1, const char *arg2, script_consumer_cb_t consumer_cb);

/** SCO audio stuff **/

static int loop_read(int sock, char *buf, ssize_t len)
{
	struct pollfd rpoll;
	int safety_timeout = 1000;
	int r;
	int ret = 0;

	rpoll.fd = sock;
	rpoll.events = POLLIN | POLLERR;
	rpoll.revents = 0;
	while (len > 0) {
		r = poll(&rpoll, 1, safety_timeout);

		if (r < 0 && errno == EINTR) {
			continue;
		}

		if (r < 0) {
			return r;
		}

		if (!r) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Timed out in loop_read for fd %d\n", sock);
			return ret;
		}

		if (rpoll.revents & POLLERR) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "POLLERR in loop_read for fd %d\n", sock);
			return ret;
		}

		if (rpoll.revents & POLLIN) {
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
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "No events out in loop_read for fd %d\n", sock);
		}
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
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Sending %s -> %s\n", bt_audio_strtype(msg->type), bt_audio_strname(msg->name));
	r = loop_write(servicefd, (char *)msg, msg->length);
	if (r < 0) {
		perror("write");
		return -1;
	}
	if (r != msg->length) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Only wrote %d bytes out of %d\n", r, msg->length);
		return -1;
	}
	return 0;
}

static int read_message(int svcsock, bt_audio_msg_header_t *msg, size_t max)
{
	ssize_t r = 0;
	size_t payloadlen = 0;
	char *payload = 0;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Trying to receive message from audio service\n");

	r = loop_read(svcsock, (char *)msg, sizeof(*msg));

	if (r < 0) {
		perror("read");
		return -1;
	}

	if (!r) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Bluez server closed the connection\n");
		return -1;
	}

	if (r != sizeof(*msg)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "read only %d out of %d bytes, discarding ...\n", r, sizeof(*msg));
		return -1;
	}

	if (msg->length > max) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Not enough room to fit %d bytes, only room for %d, discarding ...\n", r, max);
		return -1;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Received %s <- %s of length %d ... reading payload ...\n", bt_audio_strtype(msg->type), bt_audio_strname(msg->name), msg->length);
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
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Finished receiving %s <- %s of length %d\n", bt_audio_strtype(msg->type), bt_audio_strname(msg->name), msg->length);
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
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to get capabilities\n");
		return -1;
	}

	bytes_left = msg.rsp.h.length - sizeof(msg.rsp);
	codec = (codec_capabilities_t *)msg.rsp.data;

	if (bytes_left < sizeof(*codec)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%lu bytes are not enough to hold codec data of length %lu\n", 
				(unsigned long)bytes_left, (unsigned long)sizeof(*codec));
		return -1;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Payload size is %lu %lu\n", (unsigned long)bytes_left, (unsigned long)sizeof(*codec));

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Codec Seid: %d\n", codec->seid);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Codec Transport: %d\n", codec->transport);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Codec Type: %d\n", codec->type);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Codec Length: %d\n", codec->length);
	
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
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to open device %s\n", obj);
		return -1;
	}

	/* at this point device is open. It seems for HFP we always have: LINEAR16, 1 channel at 8khz
	 * is time to configure ...  */
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
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to configure device %s\n", obj);
		return -1;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Device %s configured successfuly, MTU = %d\n", obj, msg.setconf_rsp.link_mtu);
	if (msg.setconf_rsp.link_mtu != SCO_PCM_MTU) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unsupported MTU %d, we support %d\n", msg.setconf_rsp.link_mtu, SCO_PCM_MTU);
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
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to start streaming from device %s\n", obj);
		return -1;
	}

	r = read_message(servicefd, &msg.stream_ind.h, sizeof(msg));
	if (r < 0) {
		return r;
	}
	if (msg.stream_ind.h.type != BT_INDICATION 
	    || msg.stream_ind.h.name != BT_NEW_STREAM) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Stream indication error on device %s\n", obj);
		return -1;
	}

	pcmsock = bt_audio_service_get_data_fd(servicefd);
	if (pcmsock < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to retrieve pcm socket for device %s\n", obj);
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
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Got pcm socket %d!\n", pcmsock);
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

/* 
   State methods they get called when the state changes to the specific state 
   returning SWITCH_STATUS_SUCCESS tells the core to execute the standard state method next
   so if you fully implement the state you can return SWITCH_STATUS_FALSE to skip it.
*/
static switch_status_t channel_on_init(switch_core_session_t *session)
{
	switch_channel_t *channel;
	ofono_modem_t *modem = NULL;

	modem = switch_core_session_get_private(session);
	switch_assert(modem != NULL);

	channel = switch_core_session_get_channel(session);
	switch_assert(channel != NULL);

	switch_set_flag_locked(modem, TFLAG_IO);

	/* Move channel's state machine to ROUTING. This means the call is trying
	   to get from the initial start where the call because, to the point
	   where a destination has been identified. If the channel is simply
	   left in the initial state, nothing will happen. */
	switch_channel_set_state(channel, CS_ROUTING);
	switch_mutex_lock(globals.mutex);
	globals.calls++;
	switch_mutex_unlock(globals.mutex);

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_on_routing(switch_core_session_t *session)
{
	switch_channel_t *channel = NULL;
	ofono_modem_t *modem = NULL;

	channel = switch_core_session_get_channel(session);
	switch_assert(channel != NULL);

	modem = switch_core_session_get_private(session);
	switch_assert(modem != NULL);

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%s CHANNEL ROUTING\n", switch_channel_get_name(channel));

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_on_execute(switch_core_session_t *session)
{

	switch_channel_t *channel = NULL;
	ofono_modem_t *modem = NULL;

	channel = switch_core_session_get_channel(session);
	switch_assert(channel != NULL);

	modem = switch_core_session_get_private(session);
	switch_assert(modem != NULL);

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%s CHANNEL EXECUTE\n", switch_channel_get_name(channel));

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_on_destroy(switch_core_session_t *session)
{
	switch_channel_t *channel = NULL;
	ofono_modem_t *modem = NULL;

	channel = switch_core_session_get_channel(session);
	switch_assert(channel != NULL);

	modem = switch_core_session_get_private(session);

	if (modem) {
		if (switch_core_codec_ready(&modem->read_codec)) {
			switch_core_codec_destroy(&modem->read_codec);
		}

		if (switch_core_codec_ready(&modem->write_codec)) {
			switch_core_codec_destroy(&modem->write_codec);
		}
		modem->session = NULL;
	}
	return SWITCH_STATUS_SUCCESS;
}

static void modem_start_stream(ofono_modem_t *modem)
{
	modem->audio_fd = start_stream(modem->audio_service_fd, modem->bluez_path);
	if (modem->audio_fd < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to start streaming on modem %s\n", modem->name);
		switch_set_flag_locked(modem, TFLAG_HANGUP);
		return;
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Streaming on modem %s started with fd %d\n", modem->name, modem->audio_fd);
}

static void modem_stop_stream(ofono_modem_t *modem)
{
	if (modem->audio_fd >= 0) {
		close(modem->audio_fd);
		stop_stream(modem->audio_service_fd, modem->bluez_path);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Stopped streaming on modem %s with fd %d\n", modem->name, modem->audio_fd);
		modem->audio_fd = -1;
	}
}

static switch_status_t channel_on_hangup(switch_core_session_t *session)
{
	switch_channel_t *channel = NULL;
	ofono_modem_t *modem = NULL;

	channel = switch_core_session_get_channel(session);
	switch_assert(channel != NULL);

	modem = switch_core_session_get_private(session);
	switch_assert(modem != NULL);

	switch_clear_flag_locked(modem, TFLAG_IO);

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%s CHANNEL HANGUP\n", switch_channel_get_name(channel));

	switch_mutex_lock(modem->mutex);
	if (!modem->got_hangup) {
		modem_stop_stream(modem);
		execute_script(NULL, HANGUP_SCRIPT, modem->name, NULL, NULL);
		modem->got_hangup = 1;
	}
	switch_mutex_unlock(modem->mutex);

	switch_mutex_lock(globals.mutex);
	globals.calls--;
	if (globals.calls < 0) {
		globals.calls = 0;
	}
	switch_mutex_unlock(globals.mutex);

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_kill_channel(switch_core_session_t *session, int sig)
{
	switch_channel_t *channel = NULL;
	ofono_modem_t *modem = NULL;

	channel = switch_core_session_get_channel(session);
	switch_assert(channel != NULL);

	modem = switch_core_session_get_private(session);
	switch_assert(modem != NULL);

	switch (sig) {
	case SWITCH_SIG_KILL:
		switch_set_flag_locked(modem, TFLAG_IO);
		break;
	case SWITCH_SIG_BREAK:
		switch_set_flag_locked(modem, TFLAG_BREAK);
		break;
	default:
		break;
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "CHANNEL KILL %d\n", sig);
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_on_exchange_media(switch_core_session_t *session)
{
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "CHANNEL LOOPBACK\n");
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_on_soft_execute(switch_core_session_t *session)
{
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "CHANNEL TRANSMIT\n");
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_send_dtmf(switch_core_session_t *session, const switch_dtmf_t *dtmf)
{
	ofono_modem_t *modem = switch_core_session_get_private(session);
	switch_assert(modem != NULL);

	return SWITCH_STATUS_SUCCESS;
}

#define FIXED_READ_SIZE 320
static switch_status_t channel_read_frame(switch_core_session_t *session, switch_frame_t **frame, switch_io_flag_t flags, int stream_id)
{
	switch_channel_t *channel = NULL;
	ofono_modem_t *modem = NULL;
	switch_byte_t *dataptr;
	union {
		bt_audio_msg_header_t h;
		bt_audio_error_t error;
		uint8_t buf[BT_SUGGESTED_BUFFER_SIZE];
	} msg;
	struct pollfd svcpoll[2];
	uint8_t pcmbuf[SCO_PCM_MTU];
	int rc = 0;
	int len = 0;
	int diff = 0;

	channel = switch_core_session_get_channel(session);
	switch_assert(channel != NULL);

	modem = switch_core_session_get_private(session);
	switch_assert(modem != NULL);

	if (switch_test_flag(modem, TFLAG_HANGUP)) {
		return SWITCH_STATUS_GENERR;
	}

	if (modem->audio_fd < 0) {
		goto do_cng;
	}

	modem->read_frame.datalen = 0;
	modem->read_frame.flags = SFF_NONE;
	*frame = NULL;

	modem->readcnt++;
	if (!(modem->readcnt % 1000)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "modem %s read: %llu\n", modem->name, modem->readcnt);
	}

	dataptr = (switch_byte_t *)modem->read_frame.data;
	if (modem->pcm_read_buf_len) {
		memcpy(dataptr, modem->pcm_read_buf, modem->pcm_read_buf_len);
		dataptr += modem->pcm_read_buf_len;
		modem->pcm_read_buf_len = 0;
	}
	for ( ; ; ) {

		if (!switch_test_flag(modem, TFLAG_IO)) {
			return SWITCH_STATUS_FALSE;
		}

		if (switch_test_flag(modem, TFLAG_BREAK)) {
			switch_clear_flag(modem, TFLAG_BREAK);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "break modem %s doing CNG\n", modem->name);
			goto do_cng;
		}

		svcpoll[0].fd = modem->audio_fd;
		svcpoll[0].events = POLLIN | POLLERR;
		svcpoll[0].revents = 0;
#if 0
		svcpoll[1].fd = modem->audio_service_fd;
		svcpoll[1].events = POLLIN | POLLERR;
		svcpoll[1].revents = 0;
		rc = poll(svcpoll, 2, 100);
#else
		rc = poll(svcpoll, 1, 100);
#endif

		if (rc < 0) {
			if (errno == EINTR) {
				break;
			}
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error polling audio connection: %s\n", strerror(errno));
			break;
		}

		if (!rc) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "modem %s audio timed out, doing CNG\n", modem->name);
			goto do_cng;
		}

		if ((svcpoll[0].revents & POLLERR)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "POLLERR in audio connection, stopping audio stream in modem %s\n", modem->name);
			modem_stop_stream(modem);
			break;
		}

#if 0
		if ((svcpoll[1].revents & POLLERR)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "POLLERR in service connection\n");
			break;
		}

		if ((svcpoll[1].revents & POLLIN)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Reading bluez audio service message\n");
			rc = read_message(modem->audio_service_fd, &msg.h, sizeof(msg));
			if (rc < 0) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to read bluez audio service message\n");
				break;
			}
		}
#endif

		if ((svcpoll[0].revents & POLLIN)) {

			rc = read(modem->audio_fd, pcmbuf, sizeof(pcmbuf));

			if (rc < 0) {
				if (errno == EBADF) {
					/* we get this when bluez closes the audio fd on hangup before we see the hangup message */
					break;
				}
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error reading from audio connection: %s\n", strerror(errno));
				break;
			}

			if (rc != sizeof(pcmbuf)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Short read from audio connection (%d bytes)\n", rc);
			}

			/* check if we have enough to return a frame */
			len = modem->read_frame.datalen + rc;
			if (len >= FIXED_READ_SIZE) {
				diff = len - FIXED_READ_SIZE;
				len = rc - diff;
				memcpy(dataptr, pcmbuf, len);
				modem->read_frame.datalen += rc;
				memcpy(modem->pcm_read_buf, &pcmbuf[len], diff);
				modem->pcm_read_buf_len = len;
				break;
			}
			memcpy(dataptr, pcmbuf, rc);
			dataptr += rc;
			modem->read_frame.datalen += rc;
#if 0
			rc = write(modem->audio_fd, pcmbuf, rc);
			if (rc < 0) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error writing to audio connection: %s\n", strerror(errno));
				break;
			}
			if (rc != sizeof(pcmbuf)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Short write to audio connection (%d bytes)\n", rc);
			}
#endif
		}

	}

	*frame = &modem->read_frame;
	return SWITCH_STATUS_SUCCESS;

do_cng:
	dataptr = (switch_byte_t *) modem->read_frame.data;
	dataptr[0] = 65;
	dataptr[1] = 0;
	modem->read_frame.datalen = 2;
	modem->read_frame.flags = SFF_CNG;
	*frame = &modem->read_frame;
	return SWITCH_STATUS_SUCCESS;

}

static switch_status_t channel_write_frame(switch_core_session_t *session, switch_frame_t *frame, switch_io_flag_t flags, int stream_id)
{
	switch_channel_t *channel = NULL;
	ofono_modem_t *modem = NULL;
	uint8_t pcmbuf[SCO_PCM_MTU];
	char *dataptr = NULL;
	int datalen = 0;
	int rc = 0;

	channel = switch_core_session_get_channel(session);
	switch_assert(channel != NULL);

	modem = switch_core_session_get_private(session);
	switch_assert(modem != NULL);

	if (!switch_test_flag(modem, TFLAG_IO)) {
		return SWITCH_STATUS_FALSE;
	}

	if (switch_test_flag(modem, TFLAG_HANGUP)) {
		return SWITCH_STATUS_GENERR;
	}

	if (modem->audio_fd < 0) {
		return SWITCH_STATUS_SUCCESS;
	}

	if (frame->datalen == 2) {
		return SWITCH_STATUS_SUCCESS;
	}

	switch_assert(frame->datalen >= SCO_PCM_MTU);

//#if SWITCH_BYTE_ORDER == __BIG_ENDIAN
#if 0
	switch_swap_linear(frame->data, (int) frame->datalen / 2);
#endif
	if (modem->pcm_write_buf_len) {
		datalen = SCO_PCM_MTU - modem->pcm_write_buf_len;
		dataptr = pcmbuf;
		memcpy(dataptr, modem->pcm_write_buf, modem->pcm_write_buf_len);
		dataptr += modem->pcm_write_buf_len;
		memcpy(dataptr, frame->data, datalen);
		modem->pcm_write_buf_len = 0;

		rc = write(modem->audio_fd, pcmbuf, SCO_PCM_MTU);
		if (rc < 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Failed to write to modem %s: %s\n", modem->name, strerror(errno));
			return SWITCH_STATUS_GENERR;
		}
		if (rc != SCO_PCM_MTU) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Short write to modem %s of %d bytes\n", modem->name, rc);
			return SWITCH_STATUS_GENERR;
		}
		/* continue writing the frame where left */
		dataptr = frame->data + datalen;
		datalen = frame->datalen - datalen;
	} else {
		/* nothing on modem write buffer, we can start from the beginning of the frame */
		dataptr = frame->data + datalen;
		datalen = frame->datalen;
	}

	/* write the data in the expected chunks */
	while (datalen >= SCO_PCM_MTU) {
		rc = write(modem->audio_fd, dataptr, SCO_PCM_MTU);
		if (rc < 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Failed to write to modem %s: %s\n", modem->name, strerror(errno));
			return SWITCH_STATUS_GENERR;
		}
		if (rc != SCO_PCM_MTU) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Short write to modem %s of %d bytes\n", modem->name, rc);
			break;
		}
		datalen -= SCO_PCM_MTU;
		dataptr += SCO_PCM_MTU;
	}

	if (datalen) {
		memcpy(modem->pcm_write_buf, dataptr, datalen);
		modem->pcm_write_buf_len = datalen;
	}

	modem->writecnt++;
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_receive_message(switch_core_session_t *session, switch_core_session_message_t *msg)
{
	switch_channel_t *channel;
	ofono_modem_t *modem;

	channel = switch_core_session_get_channel(session);
	switch_assert(channel != NULL);

	modem = switch_core_session_get_private(session);
	switch_assert(modem != NULL);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "receiving message %d in modem %s\n", msg->message_id, modem->name);

	switch (msg->message_id) {
	case SWITCH_MESSAGE_INDICATE_ANSWER:
		{
			switch_mutex_lock(modem->mutex);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Answering modem %s\n", modem->name);
			execute_script(NULL, ANSWER_SCRIPT, modem->name, NULL, NULL);
			/* we do not start audio streaming until we get VoiceCall event with state == active */
			switch_mutex_unlock(modem->mutex);
		}
		break;
	default:
		break;
	}

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t modem_init(ofono_modem_t *modem, const char *call_name, switch_core_session_t *session)
{
	switch_status_t status;

	switch_mutex_lock(modem->mutex);

	if (modem->session) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Modem %s already has a session!\n", modem->name);
		goto err;
	}


	/* initialize the codec */
	status = switch_core_codec_init(&modem->read_codec, "L16", NULL, 
			MODEM_RATE, MODEM_INTERVAL, 
			1, SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE,
			NULL, switch_core_session_get_private(session));
	if (status != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Modem %s failed to initialize its read codec!\n", modem->name);
		goto err;
	}

	status = switch_core_codec_init(&modem->write_codec, "L16", NULL, 
			MODEM_RATE, MODEM_INTERVAL, 
			1, SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE,
			NULL, switch_core_session_get_private(session));
	if (status != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Modem %s failed to initialize its write codec!\n", modem->name);
		switch_core_codec_destroy(&modem->read_codec);
		goto err;
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Set codec L16 %dHz %dms\n", MODEM_RATE, MODEM_INTERVAL);
	switch_core_session_set_read_codec(session, &modem->read_codec);
	switch_core_session_set_write_codec(session, &modem->write_codec);

	/* setup the read frame */
	modem->read_frame.codec = &modem->read_codec;
	modem->read_frame.data = modem->databuf;
	modem->read_frame.buflen = sizeof(modem->databuf);
	modem->readcnt = 1000;
	modem->writecnt = 1000;
	modem->got_hangup = 0;
	modem->audio_fd = -1;
	modem->pcm_read_buf_len = 0;
	modem->pcm_write_buf_len = 0;
	modem->dialing = 0;
	modem->outgoing_ack = 0;
	snprintf(modem->call_name, sizeof(modem->call_name), "%s", call_name);

	/* associate modem to session and viceversa */
	modem->session = session;
	switch_core_session_set_private(session, modem);

	switch_mutex_unlock(modem->mutex);
	return SWITCH_STATUS_SUCCESS;

err:
	switch_mutex_unlock(modem->mutex);
	return SWITCH_STATUS_GENERR;

}

static ofono_modem_t *find_modem_by_name(const char *name)
{
	switch_hash_index_t *i;
	const void *key;
	void *val;
	ofono_modem_t *modem;

	switch_mutex_lock(globals.mutex);

	/* close all audio connections to the devices */
	for (i = switch_hash_first(NULL, globals.modems); i; i = switch_hash_next(i)) {
		switch_hash_this(i, &key, NULL, &val);
		modem = val;
		if (!strcasecmp(modem->name, name)) {
			switch_mutex_unlock(globals.mutex);
			return modem;
		}
	}

	switch_mutex_unlock(globals.mutex);

	return NULL;
}


/* Make sure when you have 2 sessions in the same scope that you pass the appropriate one to the routines
   that allocate memory or you will have 1 channel with memory allocated from another channel's pool!
*/
static switch_call_cause_t channel_outgoing_channel(switch_core_session_t *session, switch_event_t *var_event,
						switch_caller_profile_t *outbound_profile,
						switch_core_session_t **new_session, switch_memory_pool_t **pool, switch_originate_flag_t flags,
						switch_call_cause_t *cancel_cause)
{
	char *argv[2];
	int argc = 0;
	int sanity = 0;
	char name[128];
	ofono_modem_t *modem = NULL;
	char *data = NULL;
	const char *dest_num = NULL;
	const char *caller_id_number = NULL;
	switch_channel_t *channel;
	switch_caller_profile_t *caller_profile;

	if (!outbound_profile) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Missing caller profile!\n");
		return SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
	}

	if (zstr(outbound_profile->destination_number)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid dial string\n");
		return SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
	}

	data = switch_core_strdup(outbound_profile->pool, outbound_profile->destination_number);

	if (!zstr(outbound_profile->destination_number)) {
		dest_num = switch_sanitize_number(switch_core_strdup(outbound_profile->pool, outbound_profile->destination_number));
	}

	if (!zstr(outbound_profile->caller_id_number)) {
		caller_id_number = switch_sanitize_number(switch_core_strdup(outbound_profile->pool, outbound_profile->caller_id_number));
	}

	if ((argc = switch_separate_string(data, '/', argv, sizeof(argv)/sizeof(argv[0]))) < 1) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid dial string\n");
		return SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
	}

	modem = find_modem_by_name(argv[0]);
	if (!modem) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot place outgoing call in unknown modem '%s'\n", argv[0]);
		return SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Placing call in modem %s (%s)\n", modem, modem->id);

	switch_mutex_lock(modem->mutex);

	if (!modem->online) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot place outgoing call in modem '%s', modem is not online!\n", argv[0]);
		goto error;
	}

	if (modem->session) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot place outgoing call in modem '%s', modem busy!\n", argv[0]);
		goto error;
	}

	if (!(*new_session = switch_core_session_request(handsfree_endpoint_interface, SWITCH_CALL_DIRECTION_OUTBOUND, flags, pool))) {
		goto error;
	}

	switch_core_session_add_stream(*new_session, NULL);
	channel = switch_core_session_get_channel(*new_session);

	if (modem_init(modem, "call-name-not-set-yet", *new_session)) {
		switch_core_session_destroy(new_session);
		goto error;
	}

	snprintf(name, sizeof(name), "handsfree/%s/%s", modem->name, outbound_profile->destination_number);
	switch_channel_set_name(channel, name);

	caller_profile = switch_caller_profile_clone(*new_session, outbound_profile);
	caller_profile->destination_number = switch_core_strdup(caller_profile->pool, switch_str_nil(dest_num));
	caller_profile->caller_id_number = switch_core_strdup(caller_profile->pool, switch_str_nil(caller_id_number));
	switch_channel_set_caller_profile(channel, caller_profile);
	modem->caller_profile = caller_profile;

	/* place the actual  call */
	modem->dialing = 1;
	modem->outgoing_ack = 0;
	execute_script(NULL, DIAL_SCRIPT, modem->name, dest_num, NULL);

	switch_mutex_unlock(modem->mutex);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Placed call in modem %s\n", modem->name);

	/* wait for ofono response */
	/* up to 5 seconds waiting for ofono response */
	sanity = 50;
	while (modem->dialing && !modem->outgoing_ack && sanity--) {
		switch_sleep(100000);
	}

	switch_mutex_lock(modem->mutex);

	if (!modem->outgoing_ack) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "No response for call placed in modem %s\n", modem->name);
		/* in case the call is still trying, hang up */
		execute_script(NULL, HANGUP_SCRIPT, modem->name, dest_num, NULL);
		goto error;
	}

	switch_mutex_unlock(modem->mutex);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Call in modem %s is in progress\n", modem->name);

	switch_channel_set_flag(channel, CF_OUTBOUND);
	switch_channel_set_state(channel, CS_INIT);

	return SWITCH_CAUSE_SUCCESS;

error:
	if (switch_core_codec_ready(&modem->read_codec)) {
		switch_core_codec_destroy(&modem->read_codec);
	}

	if (switch_core_codec_ready(&modem->write_codec)) {
		switch_core_codec_destroy(&modem->write_codec);
	}
	if (new_session) {
		switch_core_session_destroy(new_session);
	}
	modem->session = NULL;
	modem->dialing = 0;
	switch_mutex_unlock(modem->mutex);
	return SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
}

static switch_status_t channel_receive_event(switch_core_session_t *session, switch_event_t *event)
{
	struct ofono_modem_t *modem = switch_core_session_get_private(session);
	char *body = switch_event_get_body(event);

	switch_assert(modem != NULL);

	if (!body) {
		body = "";
	}

	return SWITCH_STATUS_SUCCESS;
}



switch_state_handler_table_t handsfree_state_handlers = {
	/*.on_init */ channel_on_init,
	/*.on_routing */ channel_on_routing,
	/*.on_execute */ channel_on_execute,
	/*.on_hangup */ channel_on_hangup,
	/*.on_exchange_media */ channel_on_exchange_media,
	/*.on_soft_execute */ channel_on_soft_execute,
	/*.on_consume_media */ NULL,
	/*.on_hibernate */ NULL,
	/*.on_reset */ NULL,
	/*.on_park */ NULL,
	/*.on_reporting */ NULL,
	/*.on_destroy */ channel_on_destroy
};

switch_io_routines_t handsfree_io_routines = {
	/*.outgoing_channel */ channel_outgoing_channel,
	/*.read_frame */ channel_read_frame,
	/*.write_frame */ channel_write_frame,
	/*.kill_channel */ channel_kill_channel,
	/*.send_dtmf */ channel_send_dtmf,
	/*.receive_message */ channel_receive_message,
	/*.receive_event */ channel_receive_event
};


static int setup_sco_audio(ofono_modem_t *modem)
{
	/* connect to the audio service*/
	modem->audio_service_fd = bt_audio_service_open();
	if (modem->audio_service_fd < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Failed to open audio service connection for modem %s\n", modem->name);
		return -1;
	}

	if (print_caps(modem->audio_service_fd, modem->bluez_path)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Could not get capabilities for modem %s, make sure the path is correct: %s\n", modem->name, modem->bluez_path);
		bt_audio_service_close(modem->audio_service_fd);
		return -1;
	}

	if (open_device(modem->audio_service_fd, modem->bluez_path)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Could not open audio for modem %s, make sure the path is correct: %s\n", modem->name, modem->bluez_path);
		bt_audio_service_close(modem->audio_service_fd);
		return -1;
	}
	return 0;
}

static switch_status_t load_config(void)
{
	char *cf = "handsfree.conf";
	int modem_i = 0;
	switch_xml_t cfg, xml, settings, param, modems, mymodem;

	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", cf);
		return SWITCH_STATUS_TERM;
	}

	if ((settings = switch_xml_child(cfg, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");
			if (!strcasecmp(var, "dialplan")) {
				strcpy(globals.dialplan, val);
			}
			else if (!strcasecmp(var, "context")) {
				strcpy(globals.context, val);
			}
		}
	}

	if ((modems = switch_xml_child(cfg, "modems"))) {
		for (mymodem = switch_xml_child(modems, "modem"); mymodem; mymodem = mymodem->next) {
			ofono_modem_t *modem = &globals.modems_array[modem_i];
			char *name = (char *)switch_xml_attr_soft(mymodem, "name");

			if (!name) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Ignoring modem entry without name attribute\n");
				continue;
			}

			modem = switch_core_hash_find(globals.modems, name);
			if (modem) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Modem '%s' is already configured\n", name);
				continue;
			}

			modem = &globals.modems_array[modem_i];
			memset(modem, 0, sizeof(*modem));
			snprintf(modem->name, sizeof(modem->name), "%s", name);
			snprintf(modem->dialplan, sizeof(modem->dialplan), "%s", "XML");
			snprintf(modem->context, sizeof(modem->context), "%s", "public");
			modem->audio_service_fd = -1;

			for (param = switch_xml_child(mymodem, "param"); param; param = param->next) {
				char *var = (char *) switch_xml_attr_soft(param, "name");
				char *val = (char *) switch_xml_attr_soft(param, "value");
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "modem %s -> %s = %s\n", modem->id, var, val);
				if (!strcasecmp(var, "dialplan")) {
					snprintf(modem->dialplan, sizeof(modem->dialplan), "%s", val);
				}
				else if (!strcasecmp(var, "context")) {
					snprintf(modem->context, sizeof(modem->context), "%s", val);
				} 
			}
			
			switch_core_hash_insert(globals.modems, name, modem);

			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Added modem '%s'\n", modem->name);

			switch_mutex_init(&modem->mutex, SWITCH_MUTEX_NESTED, globals.module_pool);
			switch_mutex_init(&modem->flag_mutex, SWITCH_MUTEX_NESTED, globals.module_pool);
			modem_i++;
			if (modem_i == switch_arraylen(globals.modems_array)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Maximum number of modems reached, "
						"not processing more modem entries in configuration!\n");
				break;
			}
		}
	}

	switch_xml_free(xml);

	return SWITCH_STATUS_SUCCESS;
}

static void execute_script(switch_stream_handle_t *stream, char *script, const char *arg1, const char *arg2, script_consumer_cb_t consumer_cb)
{
	char cmdpath[1024];
	char linebuf[2048];
	char *eol = NULL;
	char *lineptr = NULL;
	struct pollfd fdset;
	int linelen = 0;
	int rc = 0;
	int tofs[2];
	int fromfs[2];
	int pid;
	int fd;
	char *argv[] = { script, (char *)arg1, (char *)arg2, NULL };

	snprintf(cmdpath, sizeof(cmdpath), "%s%s%s", SWITCH_GLOBAL_dirs.script_dir, SWITCH_PATH_SEPARATOR, script);

	if (pipe(tofs)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create pipe to monitor ofono events\n");
		return;
	}

	if (pipe(fromfs)) {
		close(tofs[0]);
		close(tofs[1]);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create pipe to monitor ofono events\n");
		return;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Launching command '%s' with args '%s'\n", cmdpath, arg1 ? arg1 : "");

	pid = fork();
	if (pid < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to fork to execute script '%s'\n", cmdpath);
		close(tofs[0]);
		close(tofs[1]);
		close(fromfs[0]);
		close(fromfs[1]);
		return;
	}

	if (!pid) {
		dup2(fromfs[0], STDIN_FILENO);
		dup2(tofs[1], STDOUT_FILENO);
		for (fd = STDERR_FILENO + 1; fd < 65535; fd++) {
			close(fd);
		}
		execv(cmdpath, argv);
		exit(0);
	}

	fdset.fd = tofs[0];
	fdset.events = POLLIN | POLLERR;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Waiting output of command '%s'\n", cmdpath);
	lineptr = linebuf;
	while (globals.running) {
		rc = waitpid(pid, NULL, WNOHANG);
		if (rc < 0) {
			if (errno == EINTR) {
				continue;
			}
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to wait for script '%s': %s\n", script, strerror(errno));
			break;
		}
		if (rc > 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "script '%s' terminated\n", script);
			break;
		}
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "script '%s' running\n", script);
		rc = poll(&fdset, 1, 100);
		if (rc < 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to poll output of script '%s': %s\n", script, strerror(errno));
			break;
		}
		if (!rc) {
			continue;
		}
		if (rc > 0) {
			if (POLLIN & fdset.revents) {
				rc = read(tofs[0], lineptr, sizeof(linebuf) - linelen - 1);
				if (rc < 0) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to read script '%s' output: %s\n", script, strerror(errno));
					break;
				}
				if (rc == 0) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Script '%s' did not have any output?\n", script);
					break;
				}
				linelen += rc;
				lineptr += rc;
				if (linelen >= (sizeof(linebuf) - 1)) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Too much line output from script '%s'!\n", script);
					break;
				}
				linebuf[linelen] = 0;
				/* there could potentially be more than one \n per read */
				eol = strchr(linebuf, '\n');
				if (!eol) {
					continue;
				}
				lineptr = linebuf;
				while (eol) {
					*eol = 0;
					if (stream) {
						stream->write_function(stream, "%s\n", lineptr);
					} else {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s\n", lineptr);
					}
					if (consumer_cb) {
						rc = consumer_cb(lineptr);
						if (rc) {
							switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Consumer callback requested to stop\n");
							break;
						}
					}
					lineptr = (eol + 1);
					eol = strchr(lineptr, '\n');
				}
				linelen = strlen(lineptr);
				lineptr = ((&linebuf[0]) + linelen);
			} else if (POLLERR & fdset.revents) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Poll error when waiting for script output\n");
				break;
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unknown flags when waiting script output: %d\n", fdset.revents);
				break;
			}
		}
	}
	close(tofs[0]);
	close(tofs[1]);
	close(fromfs[0]);
	close(fromfs[1]);
	if (!globals.running) {
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
	}
}

SWITCH_STANDARD_API(handsf_function)
{
	char *argv[10];
	char *mydata;
	int argc;

	if (zstr(cmd)) {
		stream->write_function(stream, "-ERR Parameter missing");
		return SWITCH_STATUS_SUCCESS;
	}

	if (!(mydata = strdup(cmd))) {
		return SWITCH_STATUS_FALSE;
	}

	if (!(argc = switch_separate_string(mydata, ' ', argv, (sizeof(argv)/sizeof(argv[0])))) || !argv[0]) {
		goto end;
	}

	if (!strcasecmp(argv[0], "list")) {
		execute_script(stream, LIST_MODEMS_SCRIPT, NULL, NULL, NULL);
	} else {
		stream->write_function(stream, "-ERR Invalid parameter");
	}

end:
	switch_safe_free(mydata);

	return SWITCH_STATUS_SUCCESS;
}

#define NAME_PARAMETER "Name = "
#define ONLINE_PARAMETER "Online = "
static int parse_modem_line(char *line)
{
	static struct {
		char modem_id[MODEM_ID_LEN];
		char *id_str;
		ofono_modem_t *modem;
		uint8_t ignoring;
	} locals = {
		.modem_id = { 0 },
		.id_str = NULL,
		.modem = NULL,
		.ignoring = 0,
	};
	int online = 0;
	char *val = NULL;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Parsing line '%s'\n", line);
	if (line[0] == '[') {
		locals.ignoring = 0;
		locals.id_str = get_modem_id_from_line(line, locals.modem_id, sizeof(locals.modem_id));
		if (!locals.id_str) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Could not get modem from line '%s'\n", line);
			return 0;
		}
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Parsing modem '%s' runtime configuration\n", locals.id_str);
	} else if (locals.ignoring) {
		/* no matter the parameter, we're ignoring this modem */
		return 0;
	} else if ((val = strcasestr(line, NAME_PARAMETER))) {
		if (!locals.id_str) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Name with no modem in line '%s'\n", line);
			return 0;
		}
		val += strlen(NAME_PARAMETER);
		/* try to find id duplicates first, unlikely, but better safe than sorry */
		locals.modem = switch_core_hash_find(globals.modems, locals.id_str);
		if (locals.modem) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Modem %s was found twice!\n", locals.id_str);
			return -1;
		}
		/* now find a modem registered with that name */
		locals.modem = switch_core_hash_find(globals.modems, val);
		if (!locals.modem) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Ignored modem '%s' not present in configuration\n", val);
			locals.ignoring = 1;
			return 0;
		}
		/* now we create a duplicate register to find the modem by id */
		switch_core_hash_insert(globals.modems, locals.id_str, locals.modem);
		snprintf(locals.modem->id, sizeof(locals.modem->id), "%s", locals.id_str);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Modem %s has id '%s'\n", locals.modem->name, locals.modem->id);
	}
	else if ((val = strcasestr(line, ONLINE_PARAMETER))) {
		if (!locals.modem) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Online parameter with no modem in line '%s'\n", line);
			return 0;
		}
		val += strlen(ONLINE_PARAMETER);
		locals.modem->online = atoi(val);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Modem %s is %s\n", locals.modem->name, locals.modem->online ? "online" : "offline");
		/* we're done, clear the modem */
		memset(&locals, 0, sizeof(locals));
	}

	return 0;
}

static void load_modems(void)
{
	/* find the bluez path for every device and whether the device is online or not */
	execute_script(NULL, LIST_MODEMS_SCRIPT, NULL, NULL, parse_modem_line);
}

static char *skip_sender(const char *event)
{
	char *str = strchr(event, '}');
	if (!str) {
		return NULL;
	}
	str++;
	if (!*str) {
		return NULL;
	}
	str++;
	if (!*str) {
		return NULL;
	}
	return str;
}

/* searching for pattern ..../hfp/<modem-id>/.... */
static char *get_modem_id_from_line(const char *line, char *modem_id, int modem_id_len)
{
	long len = 0;
	const char *end = NULL;
	const char *str = line;
	if (!line) {
		return NULL;
	}
	while (strlen(str) > 5) {
		if (*str == '/' 
	         && *(str + 1) == 'h' 
		 && *(str + 2) == 'f' 
		 && *(str + 3) == 'p'
		 && *(str + 4) == '/') {
			str += 5;
			end = strchr(str, '/');
			if (!end) {
				end = strchr(str, ' ');
				if (!end) {
					return NULL;
				}
				goto getname;
			}
			if (end == str) {
				return NULL;
			}
getname:
			len = (long)end - (long)str;
			if (len >= modem_id_len) {
				return NULL;
			}
			memcpy(modem_id, str, len);
			modem_id[len] = 0;
			modem_id[modem_id_len-1] = 0;
			return modem_id;
		}
		str++;
	}
	return NULL;
}

static void handle_call_hangup(const char *modem_id)
{
	switch_channel_t *channel = NULL;
	switch_core_session_t *session = NULL;
	ofono_modem_t *modem = NULL;
	modem = switch_core_hash_find(globals.modems, modem_id);
	if (!modem) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Hangup call in unknown modem '%s'\n", modem_id);
		return;
	}

	switch_mutex_lock(modem->mutex);

	modem_stop_stream(modem);

	session = modem->session;

	if (modem->got_hangup) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Hangup ack in modem '%s'\n", modem_id);
		/* is a hangup ack from the hangup we originated */
		modem->got_hangup = 0;
		switch_mutex_unlock(modem->mutex);
		return;
	}
	
	/* modem is requesting us to hangup the call, send hangup to the session */
	if (!modem->session) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Hangup call in modem '%s' without a session\n", modem_id);
		switch_mutex_unlock(modem->mutex);
		return;
	}

	modem->got_hangup = 1;

	switch_mutex_unlock(modem->mutex);

	switch_core_session_read_lock(session);
	channel = switch_core_session_get_channel(session);
	switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Hung up call in modem %s\n", modem_id);

	switch_core_session_rwunlock(session);
}

static void handle_outgoing_call(const char *modem_id, const char *call_name)
{
	ofono_modem_t *modem = NULL;

	modem = switch_core_hash_find(globals.modems, modem_id);
	if (!modem) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Outgoing call acknowledged in unknown modem '%s'\n", modem_id);
		return;
	}

	if (!modem->dialing) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Outgoing call acknowledged in modem '%s', but we did not place a call?\n", modem_id);
		return;
	}

	switch_mutex_lock(modem->mutex);

	modem->outgoing_ack = 1;
	snprintf(modem->call_name, sizeof(modem->call_name), "%s", call_name);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Outgoing call in modem %s was acknowledged with call name %s\n", modem_id, call_name);

	switch_mutex_unlock(modem->mutex);
}

static void handle_incoming_call(const char *modem_id, const char *call_name)
{
	switch_channel_t *channel = NULL;
	switch_core_session_t *session = NULL;
	ofono_modem_t *modem = NULL;
	char chan_name[128];

	modem = switch_core_hash_find(globals.modems, modem_id);
	if (!modem) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Incoming call in unknown modem '%s'\n", modem_id);
		return;
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Incoming call in modem %s\n", modem_id);

	/* notify FreeSWITCH about the incoming call */
	if (!(session = switch_core_session_request(handsfree_endpoint_interface, SWITCH_CALL_DIRECTION_INBOUND, SOF_NONE, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Session init Error!\n");
		return;
	}

	switch_core_session_add_stream(session, NULL);

	channel = switch_core_session_get_channel(session);
	if (modem_init(modem, call_name, session) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Failed to initialize modem!\n");
		switch_core_session_destroy(&session);
		return;
	}
	modem->caller_profile = switch_caller_profile_new(switch_core_session_get_pool(session),
							"HandsFree",
							"XML",
							"Moises",
							"1234",
							NULL,
							"5678",
							"5678",
							"1234",
							(char *)modname,
							"default",
							"1234");
	switch_assert(modem->caller_profile != NULL);


	snprintf(chan_name, sizeof(chan_name), "HandsFree/%s/%s", modem->name, modem->caller_profile->destination_number);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Connect inbound channel %s\n", chan_name);
	switch_channel_set_name(channel, chan_name);
	switch_channel_set_caller_profile(channel, modem->caller_profile);
#if 0
	switch_channel_set_variable(channel, "handsfree_network", "blah");
#endif

	switch_channel_set_state(channel, CS_INIT);

	/* bring the session alive! */
	if (switch_core_session_thread_launch(session) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Error spawning session thread!\n");
		switch_core_session_destroy(&session);
		return;
	}
}

#define VCM_NEW_CALL_EVENT "CallAdded"
#define VCM_HANGUP_CALL_EVENT "CallRemoved"
// Bluez device syntax: /org/bluez/26745/hci0/dev_00_1D_28_4B_9A_A8
// where does 26745 comes from? seems like a PID, where to get it from?
// hci0 is the adapter, this needs to come from configuration
// {VoiceCallManager} [CallAdded] /hfp/00158315A310_001D284B9AA8/voicecall01 { State = incoming, LineIdentification = +16478353016, Multiparty = False }
static void handle_call_manager_event(const char *event)
{
	char *event_str = NULL;
	char modem_id[MODEM_ID_LEN];
	char *modem_id_str = NULL;
	char *str = NULL;
	char *end = NULL;
	char call_name[CALL_NAME_LEN];
	long len = 0;

	event_str = skip_sender(event);
	if (!event_str) {
		return;
	}

	/* handle the actual event for VoiceCallManager */
	if (strstr(event_str, VCM_NEW_CALL_EVENT)) {
		modem_id_str = get_modem_id_from_line(event, modem_id, sizeof(modem_id));
		if (!modem_id_str) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to retrieve modem id from new call event %s\n", event);
			return;
		}
		str = strrchr(event, '/');
		str++;
		end = strchr(str, ' ');
		if (!str || !(*str) || !end) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
			"Failed to retrieve call name from new call event %s: %p, %d, %p\n", event, str, str ? *str : 0, end);
			return;
		}
		len = end - str;
		if (len >= sizeof(call_name)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Not enough room to fit call name from incoming call event %s\n", event);
			return;
		}
		memcpy(call_name, str, len);
		call_name[len] = 0;
		/* Determine whether is incoming or outgoing */
		if (strstr(event, "incoming")) {
			handle_incoming_call(modem_id, call_name);
		} else if (strstr(event, "dialing")) {
			handle_outgoing_call(modem_id, call_name);
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Do not know how to handle new call state in event '%s'\n", event);
		}
	} else if (strstr(event_str, VCM_HANGUP_CALL_EVENT)) {
		modem_id_str = get_modem_id_from_line(event, modem_id, sizeof(modem_id));
		if (!modem_id_str) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to retrieve modem name from hangup call event %s\n", event);
			return;
		}
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Hangup call in modem %s\n", modem_id_str);
		handle_call_hangup(modem_id_str);
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Ignored VoiceCallManager event: %s\n", event_str);
	}
}

#define ACTIVE_CALL "State = active"
#define ALERTING_CALL "State = alerting"
static void handle_call_event(const char *event)
{
	ofono_modem_t *modem = NULL;
	char *event_str = NULL;
	char modem_id[MODEM_ID_LEN];
	char *modem_id_str = NULL;
	switch_core_session_t *session = NULL;
	switch_channel_t *channel = NULL;

	event_str = skip_sender(event);
	if (!event_str) {
		return;
	}
	if (strstr(event, ACTIVE_CALL)) {
		modem_id_str = get_modem_id_from_line(event_str, modem_id, sizeof(modem_id));
		if (!modem_id_str) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to retrieve modem name from active call event %s, you will not hear audio!\n", event);
			return;
		}
		modem = switch_core_hash_find(globals.modems, modem_id);
		if (!modem) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Active call in unknown modem '%s'\n", modem_id);
			return;
		}
		if (!modem->session) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Active call in modem '%s' but no session!\n", modem_id);
			return;
		}
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Active call in modem %s, enabling audio!\n", modem_id);

		if (modem->dialing) {
			switch_mutex_lock(modem->mutex);

			session = modem->session;

			switch_mutex_unlock(modem->mutex);

			switch_core_session_read_lock(session);
			channel = switch_core_session_get_channel(session);
			switch_channel_mark_answered(channel);
			switch_core_session_rwunlock(session);
		}

		modem_start_stream(modem);

	} else if (strstr(event, ALERTING_CALL)) {
		modem_id_str = get_modem_id_from_line(event_str, modem_id, sizeof(modem_id));
		if (!modem_id_str) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to retrieve modem name from active call event %s, you will not hear audio!\n", event);
			return;
		}
		modem = switch_core_hash_find(globals.modems, modem_id);
		if (!modem) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Alerting call in unknown modem '%s'\n", modem_id);
			return;
		}
		if (!modem->session) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Alerting call in modem '%s' but no session!\n", modem_id);
			return;
		}
		switch_mutex_lock(modem->mutex);

		session = modem->session;

		switch_mutex_unlock(modem->mutex);
		
		switch_core_session_read_lock(session);
		channel = switch_core_session_get_channel(session);
		switch_channel_mark_ring_ready(channel);
		switch_core_session_rwunlock(session);
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Ignored voicecall event: %s\n", event);
	}
}

static void handle_modem_event(const char *event)
{
}

static void handle_call_vol_event(const char *event)
{
}

static void handle_network_reg_event(const char *event)
{
}

static void process_event(const char *event)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s\n", event);
	if (!strncasecmp(EVENT_SRC_VOICE_CALL_MANAGER, event, sizeof(EVENT_SRC_VOICE_CALL_MANAGER)-1)) {
		handle_call_manager_event(event);
	} else if (!strncasecmp(EVENT_SRC_VOICE_CALL, event, sizeof(EVENT_SRC_VOICE_CALL)-1)) {
		handle_call_event(event);
	} else if (!strncasecmp(EVENT_SRC_MODEM, event, sizeof(EVENT_SRC_MODEM)-1)) {
		handle_modem_event(event);
	} else if (!strncasecmp(EVENT_SRC_CALL_VOL, event, sizeof(EVENT_SRC_CALL_VOL)-1)) {
		handle_call_vol_event(event);
	} else if (!strncasecmp(EVENT_SRC_NETWORK_REG, event, sizeof(EVENT_SRC_NETWORK_REG)-1)) {
		handle_network_reg_event(event);
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Ignored unknown event: %s\n", event);
	}
}

static int setup_audio_connections(void);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_handsfree_runtime)
{
	int tofs[2];
	int fromfs[2];
	int pid;
	int fd;
	char *c;
	char *event;
	char *argv[] = { MONITOR_SCRIPT, NULL };
	char linebuf[2048];
	char cmdpath[1024];
	struct pollfd fdset;
	int rc = 0;

	/* update modems hash with runtime information */
	load_modems();

	/* try to open the audio socket for each modem */
	setup_audio_connections();

	snprintf(cmdpath, sizeof(cmdpath), "%s%s%s", SWITCH_GLOBAL_dirs.script_dir, SWITCH_PATH_SEPARATOR, MONITOR_SCRIPT);

	if (pipe(tofs)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create pipe to monitor ofono events\n");
		return SWITCH_STATUS_TERM;
	}

	if (pipe(fromfs)) {
		close(tofs[0]);
		close(tofs[1]);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create pipe to monitor ofono events\n");
		return SWITCH_STATUS_TERM;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Launching command %s\n", cmdpath);

	pid = fork();
	if (pid < 0) {
		close(tofs[0]);
		close(tofs[1]);
		close(fromfs[0]);
		close(fromfs[1]);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to fork to monitor ofono events\n");
		return SWITCH_STATUS_TERM;
	}

	if (!pid) {
		dup2(fromfs[0], STDIN_FILENO);
		dup2(tofs[1], STDOUT_FILENO);
		for (fd = STDERR_FILENO + 1; fd < (2^65536); fd++) {
			close(fd);
		}
		execv(cmdpath, argv);
		exit(0);
	}

	globals.thread_running = 1;
	fdset.fd = tofs[0];
	fdset.events = POLLIN | POLLERR;
	while (globals.running) {
		rc = poll(&fdset, 1, 100);
		if (rc < 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to poll ofono events: %s\n", strerror(errno));
			break;
		}
		if (!rc) {
			continue;
		}
		if (rc > 0) {
			if (POLLIN & fdset.revents) {
				rc = read(tofs[0], linebuf, sizeof(linebuf)-1);
				if (rc < 0) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to read ofono events: %s\n", strerror(errno));
					break;
				}
				if (rc == 0) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "No ofono events\n");
					break;
				}
				linebuf[rc] = 0;
				event = linebuf;
				do {
					c = strchr(event, '\n');
					if (c) {
						*c = '\0';
					}
					process_event(event);
					if (c) {
						event = c;
						event++;
					} else {
						event = NULL;
					}
				} while (event && *event);
			} else if (POLLERR & fdset.revents) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Poll error when waiting ofono events\n");
				break;
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unknown flags when waiting ofono events: %d\n", fdset.revents);
				break;
			}
		}
	}

	close(tofs[0]);
	close(tofs[1]);
	close(fromfs[0]);
	close(fromfs[1]);

	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);

	globals.thread_running = 0;
	return SWITCH_STATUS_TERM;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_handsfree_shutdown)
{
	ofono_modem_t *modem = NULL;
	switch_hash_index_t *i;
	const void *key;
	void *val;

	/* stop threads  */
	globals.running = 0;

	/* Wait monitor thread to exit */
	while (globals.thread_running) {
		switch_yield(100000);
	}

	/* close all audio connections to the devices */
	for (i = switch_hash_first(NULL, globals.modems); i; i = switch_hash_next(i)) {
		switch_hash_this(i, &key, NULL, &val);
		modem = val;
		if (modem->audio_service_fd > 0) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Closing audio connection for modem %s/%s\n", modem->name, modem->id);
			close_device(modem->audio_service_fd, modem->bluez_path);
			bt_audio_service_close(modem->audio_service_fd);
			modem->audio_service_fd = -1;
		}
	}

	switch_core_hash_destroy(&globals.modems);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Handsfree Done!\n");

	return SWITCH_STATUS_SUCCESS;
}

static int parse_device_line(char *path)
{
	/* /org/bluez/2891/hci0/dev_00_1D_28_4B_9A_A8 */
	ofono_modem_t *modem = NULL;
	switch_hash_index_t *i;
	char *line = NULL;
	const void *key;
	void *val;
	char *c = NULL;
	char *dev = NULL;
	char modem_id[MODEM_ID_LEN];
	int j = 0;

	line = strdup(path);

	dev = strrchr(line, '/');
	if (!dev) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "No slash in line %s\n", line);
	}
	dev += strlen("dev_") + 1;
	while (*dev) {
		if (*dev == '\n') {
			break;
		}
		if (*dev != '_') {
			modem_id[j++] = *dev;
		}
		dev++;
		if (j == (sizeof(modem_id) - 1)) {
			break;
		}
	}
	modem_id[j] = 0;

	/* try to find the device */
	for (i = switch_hash_first(NULL, globals.modems); i; i = switch_hash_next(i)) {
		switch_hash_this(i, &key, NULL, &val);
		modem = val;
		if (strstr(modem->id, modem_id)) {
			c = strchr(path, '\n');
			if (c) {
				*c = 0;
			}
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Found bluez path %s for modem %s/%s\n", path, modem->id, modem->name);
			snprintf(modem->bluez_path, sizeof(modem->bluez_path), "%s", path);
			break;
		}
	}
	switch_safe_free(line);
	return 0;
}

static int setup_audio_connections(void)
{
	ofono_modem_t *modem = NULL;
	switch_hash_index_t *i;
	const void *key;
	void *val;

	/* find the bluez path for each modem */
	execute_script(NULL, LIST_DEVICES_SCRIPT, NULL, NULL, parse_device_line);

	/* open all audio connections to the devices */
	for (i = switch_hash_first(NULL, globals.modems); i; i = switch_hash_next(i)) {
		switch_hash_this(i, &key, NULL, &val);
		modem = val;
		if (modem->audio_service_fd < 0 ) {
			if (!strlen(modem->bluez_path)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "No audio path for modem %s/%s was found!\n", modem->name, modem->id);
				continue;
			}
			if (!modem->online) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Modem %s/%s is not online, cannot open audio connection!\n", modem->name, modem->id);
				continue;
			}
			if (setup_sco_audio(modem)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "failed to setup audio for modem %s\n", modem->name);
				continue;
			}
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Created audio connection for modem %s/%s\n", modem->name, modem->id);
		}
	}
}

#define HANDS_FREE_SYNTAX "handsfree list"
SWITCH_MODULE_LOAD_FUNCTION(mod_handsfree_load)
{
	switch_api_interface_t *commands_api_interface;
	
	memset(&globals, 0, sizeof(globals));

	globals.module_pool = pool;

	switch_mutex_init(&globals.mutex, SWITCH_MUTEX_NESTED, globals.module_pool);

	switch_core_hash_init(&globals.modems, globals.module_pool);

	/* read config */
	load_config();

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	handsfree_endpoint_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_ENDPOINT_INTERFACE);
	handsfree_endpoint_interface->interface_name = "handsfree";
	handsfree_endpoint_interface->io_routines = &handsfree_io_routines;
	handsfree_endpoint_interface->state_handler = &handsfree_state_handlers;

	SWITCH_ADD_API(commands_api_interface, "handsfree", "Hands Free Endpoint Commands", handsf_function, HANDS_FREE_SYNTAX);

	switch_console_set_complete("add handsfree list");

	/* indicate that the module should continue to be loaded */
	globals.running = 1;
	return SWITCH_STATUS_SUCCESS;
}



/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* This table contains the string representation for messages types */
static const char *strtypes[] = {
	"BT_REQUEST",
	"BT_RESPONSE",
	"BT_INDICATION",
	"BT_ERROR",
};

/* This table contains the string representation for messages names */
static const char *strnames[] = {
	"BT_GET_CAPABILITIES",
	"BT_OPEN",
	"BT_SET_CONFIGURATION",
	"BT_NEW_STREAM",
	"BT_START_STREAM",
	"BT_STOP_STREAM",
	"BT_CLOSE",
	"BT_CONTROL",
	"BT_DELAY_REPORT",
};

int bt_audio_service_open(void)
{
	int sk;
	int err;
	struct sockaddr_un addr = {
		AF_UNIX, BT_IPC_SOCKET_NAME
	};

	sk = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sk < 0) {
		err = errno;
		fprintf(stderr, "%s: Cannot open socket: %s (%d)\n",
			__FUNCTION__, strerror(err), err);
		errno = err;
		return -1;
	}

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		fprintf(stderr, "%s: connect() failed: %s (%d)\n",
			__FUNCTION__, strerror(err), err);
		close(sk);
		errno = err;
		return -1;
	}

	return sk;
}

int bt_audio_service_close(int sk)
{
	return close(sk);
}

int bt_audio_service_get_data_fd(int sk)
{
	char cmsg_b[CMSG_SPACE(sizeof(int))], m;
	int err, ret;
	struct iovec iov = { &m, sizeof(m) };
	struct msghdr msgh;
	struct cmsghdr *cmsg;

	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = &cmsg_b;
	msgh.msg_controllen = CMSG_LEN(sizeof(int));

	ret = recvmsg(sk, &msgh, 0);
	if (ret < 0) {
		err = errno;
		fprintf(stderr, "%s: Unable to receive fd: %s (%d)\n",
			__FUNCTION__, strerror(err), err);
		errno = err;
		return -1;
	}

	/* Receive auxiliary data in msgh */
	for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
			cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET
				&& cmsg->cmsg_type == SCM_RIGHTS) {
			memcpy(&ret, CMSG_DATA(cmsg), sizeof(int));
			return ret;
		}
	}

	errno = EINVAL;
	return -1;
}

const char *bt_audio_strtype(uint8_t type)
{
	if (type >= ARRAY_SIZE(strtypes))
		return NULL;

	return strtypes[type];
}

const char *bt_audio_strname(uint8_t name)
{
	if (name >= ARRAY_SIZE(strnames))
		return NULL;

	return strnames[name];
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4:
 */
