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
 * Contributor(s):
 * 
 * Anthony Minessale II <anthm@freeswitch.org>
 *
 * mod_fifo.c -- FIFO
 *
 */
#include <switch.h>

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_fifo_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_fifo_load);
SWITCH_MODULE_DEFINITION(mod_fifo, mod_fifo_load, mod_fifo_shutdown, NULL);

#define MANUAL_QUEUE_NAME "manual_calls"
#define FIFO_EVENT "fifo::info"
#define FIFO_DELAY_DESTROY 100
static switch_status_t load_config(int reload, int del_all);
#define MAX_PRI 10

typedef enum {
	NODE_STRATEGY_INVALID = -1,
	NODE_STRATEGY_RINGALL = 0,
	NODE_STRATEGY_ENTERPRISE
} outbound_strategy_t;

static outbound_strategy_t default_strategy = NODE_STRATEGY_RINGALL;


typedef struct {
	int nelm;
	int idx;
	switch_event_t **data;
	switch_memory_pool_t *pool;
	switch_mutex_t *mutex;
} fifo_queue_t;

switch_status_t fifo_queue_create(fifo_queue_t **queue, int size, switch_memory_pool_t *pool) 
{
	fifo_queue_t *q;

	q = switch_core_alloc(pool, sizeof(*q));
	q->pool = pool;
	q->nelm = size - 1;
	q->data = switch_core_alloc(pool, size * sizeof(switch_event_t *));
	switch_mutex_init(&q->mutex, SWITCH_MUTEX_NESTED, pool);
	
	*queue = q;
	
	return SWITCH_STATUS_SUCCESS;
}


static void change_pos(switch_event_t *event, int pos)
{
	const char *uuid = switch_event_get_header(event, "unique-id");
	switch_core_session_t *session;
	switch_channel_t *channel;
	char tmp[30] = "";

	if (zstr(uuid)) return;

	if (!(session = switch_core_session_locate(uuid))) {
		return;
	}
	
	channel = switch_core_session_get_channel(session);
	
	switch_snprintf(tmp, sizeof(tmp), "%d", pos);
	switch_channel_set_variable(channel, "fifo_position", tmp);
	switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "fifo_position", tmp);
	
	switch_core_session_rwunlock(session);


}

static switch_status_t fifo_queue_push(fifo_queue_t *queue, switch_event_t *ptr)
{
	switch_mutex_lock(queue->mutex);

	if (queue->idx == queue->nelm) {
		switch_mutex_unlock(queue->mutex);
		return SWITCH_STATUS_FALSE;
	}

	queue->data[queue->idx++] = ptr;


	switch_mutex_unlock(queue->mutex);

	return SWITCH_STATUS_SUCCESS;

}

static int fifo_queue_size(fifo_queue_t *queue)
{
	int s;
	switch_mutex_lock(queue->mutex);
	s = queue->idx;
	switch_mutex_unlock(queue->mutex);

	return s;
}

static switch_status_t fifo_queue_pop(fifo_queue_t *queue, switch_event_t **pop, switch_bool_t remove)
{
	int i;

	switch_mutex_lock(queue->mutex);

	if (queue->idx == 0) {
		switch_mutex_unlock(queue->mutex);
		*pop = NULL;
		return SWITCH_STATUS_FALSE;
	}

	if (remove) {
		*pop = queue->data[0];
	} else {
		switch_event_dup(pop, queue->data[0]);
	}

	if (remove) {
		for (i = 1; i < queue->idx; i++) {
			queue->data[i-1] = queue->data[i];
			queue->data[i] = NULL;
			change_pos(queue->data[i-1], i);
		}
	
		queue->idx--;
	}
	
	switch_mutex_unlock(queue->mutex);

	return SWITCH_STATUS_SUCCESS;

}


static switch_status_t fifo_queue_pop_nameval(fifo_queue_t *queue, const char *name, const char *val, switch_event_t **pop, switch_bool_t remove)
{
	int i, j;

	switch_mutex_lock(queue->mutex);

	if (queue->idx == 0 || zstr(name) || zstr(val)) {
		switch_mutex_unlock(queue->mutex);
		return SWITCH_STATUS_FALSE;
	}

	for (j = 0; j < queue->idx; j++) {
		const char *j_val = switch_event_get_header(queue->data[j], name);
		if (j_val && val && !strcmp(j_val, val)) {

			if (remove) {
				*pop = queue->data[j];
			} else {
				switch_event_dup(pop, queue->data[j]);
			}
			break;
		}
	}

	if (j == queue->idx) {
		switch_mutex_unlock(queue->mutex);
		return SWITCH_STATUS_FALSE;
	}
	
	if (remove) {
		for (i = j+1; i < queue->idx; i++) {
			queue->data[i-1] = queue->data[i];
			queue->data[i] = NULL;
			change_pos(queue->data[i-1], i);
		}
	
		queue->idx--;
	}
	
	switch_mutex_unlock(queue->mutex);

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t fifo_queue_popfly(fifo_queue_t *queue, const char *uuid)
{
	int i, j;

	switch_mutex_lock(queue->mutex);

	if (queue->idx == 0 || zstr(uuid)) {
		switch_mutex_unlock(queue->mutex);
		return SWITCH_STATUS_FALSE;
	}

	for (j = 0; j < queue->idx; j++) {
		const char *j_uuid = switch_event_get_header(queue->data[j], "unique-id");
		if (j_uuid && !strcmp(j_uuid, uuid)) break;
	}

	if (j == queue->idx) {
		switch_mutex_unlock(queue->mutex);
		return SWITCH_STATUS_FALSE;
	}

	for (i = j+1; i < queue->idx; i++) {
		queue->data[i-1] = queue->data[i];
		queue->data[i] = NULL;
		change_pos(queue->data[i-1], i);
	}
	
	queue->idx--;
	
	switch_mutex_unlock(queue->mutex);

	return SWITCH_STATUS_SUCCESS;

}



struct fifo_node {
	char *name;
	switch_mutex_t *mutex;
	fifo_queue_t *fifo_list[MAX_PRI];
	switch_hash_t *consumer_hash;
	int caller_count;
	int consumer_count;
	int ring_consumer_count;
	switch_time_t start_waiting;
	uint32_t importance;
	switch_thread_rwlock_t *rwlock;
	switch_memory_pool_t *pool;
	int has_outbound;
	int ready;
	int busy;
	int is_static;
	int outbound_per_cycle;
	char *outbound_name;
	outbound_strategy_t outbound_strategy;
};

typedef struct fifo_node fifo_node_t;

struct callback {
	char *buf;
	size_t len;
	int matches;
};
typedef struct callback callback_t;

static const char *strat_parse(outbound_strategy_t s)
{
	switch (s) {
	case NODE_STRATEGY_RINGALL:
		return "ringall";
	case NODE_STRATEGY_ENTERPRISE:
		return "enterprise";
	default:
		break;
	}
	
	return "invalid";
}

static outbound_strategy_t parse_strat(const char *name)
{
	if (!strcasecmp(name, "ringall")) {
		return NODE_STRATEGY_RINGALL;
	}

	if (!strcasecmp(name, "enterprise")) {
		return NODE_STRATEGY_ENTERPRISE;
	}

	return NODE_STRATEGY_INVALID;
}

static int sql2str_callback(void *pArg, int argc, char **argv, char **columnNames)
{
	callback_t *cbt = (callback_t *) pArg;

	switch_copy_string(cbt->buf, argv[0], cbt->len);
	cbt->matches++;
	return 0;
}

static switch_bool_t match_key(const char *caller_exit_key, char key)
{
	while (caller_exit_key && *caller_exit_key) {
		if (*caller_exit_key++ == key) {
			return SWITCH_TRUE;
		}
	}
	return SWITCH_FALSE;
}

static switch_status_t on_dtmf(switch_core_session_t *session, void *input, switch_input_type_t itype, void *buf, unsigned int buflen)
{
	switch_core_session_t *bleg = (switch_core_session_t *) buf;

	switch (itype) {
	case SWITCH_INPUT_TYPE_DTMF:
		{
			switch_dtmf_t *dtmf = (switch_dtmf_t *) input;
			switch_channel_t *bchan = switch_core_session_get_channel(bleg);
			switch_channel_t *channel = switch_core_session_get_channel(session);

			const char *consumer_exit_key = switch_channel_get_variable(channel, "fifo_consumer_exit_key");

			if (switch_channel_test_flag(switch_core_session_get_channel(session), CF_BRIDGE_ORIGINATOR)) {
				if (consumer_exit_key && dtmf->digit == *consumer_exit_key) {
					switch_channel_hangup(bchan, SWITCH_CAUSE_NORMAL_CLEARING);
					return SWITCH_STATUS_BREAK;
				} else if (!consumer_exit_key && dtmf->digit == '*') {
					switch_channel_hangup(bchan, SWITCH_CAUSE_NORMAL_CLEARING);
					return SWITCH_STATUS_BREAK;
				} else if (dtmf->digit == '0') {
					const char *moh_a = NULL, *moh_b = NULL;

					if (!(moh_b = switch_channel_get_variable(bchan, "fifo_music"))) {
						moh_b = switch_channel_get_variable(bchan, "hold_music");
					}

					if (!(moh_a = switch_channel_get_variable(channel, "fifo_hold_music"))) {
						if (!(moh_a = switch_channel_get_variable(channel, "fifo_music"))) {
							moh_a = switch_channel_get_variable(channel, "hold_music");
						}
					}

					switch_ivr_soft_hold(session, "0", moh_a, moh_b);
					return SWITCH_STATUS_IGNORE;
				}
			}
		}
		break;
	default:
		break;
	}

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t moh_on_dtmf(switch_core_session_t *session, void *input, switch_input_type_t itype, void *buf, unsigned int buflen)
{
	switch (itype) {
	case SWITCH_INPUT_TYPE_DTMF:
		{
			switch_dtmf_t *dtmf = (switch_dtmf_t *) input;
			switch_channel_t *channel = switch_core_session_get_channel(session);
			const char *caller_exit_key = switch_channel_get_variable(channel, "fifo_caller_exit_key");

			if (match_key(caller_exit_key, dtmf->digit)) {
				char *bp = buf;
				*bp = dtmf->digit;
				return SWITCH_STATUS_BREAK;
			}
		}
		break;
	default:
		break;
	}

	return SWITCH_STATUS_SUCCESS;
}

#define check_string(s) if (!zstr(s) && !strcasecmp(s, "undef")) { s = NULL; }

static int node_consumer_wait_count(fifo_node_t *node)
{
	int i, len = 0;

	for (i = 0; i < MAX_PRI; i++) {
		len += fifo_queue_size(node->fifo_list[i]);
	}

	return len;
}

static void node_remove_uuid(fifo_node_t *node, const char *uuid)
{
	int i = 0;

	for (i = 0; i < MAX_PRI; i++) {
		fifo_queue_popfly(node->fifo_list[i], uuid);
	}

	if (!node_consumer_wait_count(node)) {
		node->start_waiting = 0;
	}

	return;
}

#define MAX_CHIME 25
struct fifo_chime_data {
	char *list[MAX_CHIME];
	int total;
	int index;
	time_t next;
	int freq;
	int abort;
	time_t orbit_timeout;
	int do_orbit;
	char *orbit_exten;
	char *orbit_dialplan;
	char *orbit_context;
};

typedef struct fifo_chime_data fifo_chime_data_t;

static switch_status_t caller_read_frame_callback(switch_core_session_t *session, switch_frame_t *frame, void *user_data)
{
	fifo_chime_data_t *cd = (fifo_chime_data_t *) user_data;

	if (!cd) {
		return SWITCH_STATUS_SUCCESS;
	}

	if (cd->total && switch_epoch_time_now(NULL) >= cd->next) {
		if (cd->index == MAX_CHIME || cd->index == cd->total || !cd->list[cd->index]) {
			cd->index = 0;
		}

		if (cd->list[cd->index]) {
			switch_input_args_t args = { 0 };
			char buf[25] = "";
			switch_channel_t *channel = switch_core_session_get_channel(session);
			const char *caller_exit_key = switch_channel_get_variable(channel, "fifo_caller_exit_key");
			args.input_callback = moh_on_dtmf;
			args.buf = buf;
			args.buflen = sizeof(buf);

			if (switch_ivr_play_file(session, NULL, cd->list[cd->index], &args) != SWITCH_STATUS_SUCCESS) {
				return SWITCH_STATUS_FALSE;
			}

			if (match_key(caller_exit_key, *buf)) {
				cd->abort = 1;
				return SWITCH_STATUS_FALSE;
				switch_channel_set_variable(channel, "fifo_caller_exit_key", (char *)buf);
			}
			cd->next = switch_epoch_time_now(NULL) + cd->freq;
			cd->index++;
		}
	} else if (cd->orbit_timeout && switch_epoch_time_now(NULL) >= cd->orbit_timeout) {
		cd->do_orbit = 1;
		return SWITCH_STATUS_FALSE;
	}

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t consumer_read_frame_callback(switch_core_session_t *session, switch_frame_t *frame, void *user_data)
{
	fifo_node_t *node, **node_list = (fifo_node_t **) user_data;
	int x = 0, total = 0, i = 0;

	for (i = 0;; i++) {
		if (!(node = node_list[i])) {
			break;
		}
		for (x = 0; x < MAX_PRI; x++) {
			total += fifo_queue_size(node->fifo_list[x]);
		}
	}

	if (total) {
		return SWITCH_STATUS_FALSE;
	}

	return SWITCH_STATUS_SUCCESS;
}

static struct {
	switch_hash_t *fifo_hash;
	switch_mutex_t *mutex;
	switch_mutex_t *sql_mutex;
	switch_memory_pool_t *pool;
	int running;
	switch_event_node_t *node;
	char hostname[256];
	char *dbname;
	char *odbc_dsn;
	char *odbc_user;
	char *odbc_pass;
	int node_thread_running;
	switch_odbc_handle_t *master_odbc;
} globals;


switch_cache_db_handle_t *fifo_get_db_handle(void)
{
	switch_cache_db_connection_options_t options = { {0} };
	switch_cache_db_handle_t *dbh = NULL;

	if (!zstr(globals.odbc_dsn)) {
		options.odbc_options.dsn = globals.odbc_dsn;
		options.odbc_options.user = globals.odbc_user;
		options.odbc_options.pass = globals.odbc_pass;

		if (switch_cache_db_get_db_handle(&dbh, SCDB_TYPE_ODBC, &options) != SWITCH_STATUS_SUCCESS) {
			dbh = NULL;
		}
		return dbh;
	} else {
		options.core_db_options.db_path = globals.dbname;
		if (switch_cache_db_get_db_handle(&dbh, SCDB_TYPE_CORE_DB, &options) != SWITCH_STATUS_SUCCESS) {
			dbh = NULL;
		}
		return dbh;
	}
}


static switch_status_t fifo_execute_sql(char *sql, switch_mutex_t *mutex)
{
	switch_cache_db_handle_t *dbh = NULL;
	switch_status_t status = SWITCH_STATUS_FALSE;

	if (mutex) {
		switch_mutex_lock(mutex);
	}

	if (!(dbh = fifo_get_db_handle())) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error Opening DB\n");
		goto end;
	}

	status = switch_cache_db_execute_sql(dbh, sql, NULL);

  end:

	switch_cache_db_release_db_handle(&dbh);

	if (mutex) {
		switch_mutex_unlock(mutex);
	}

	return status;
}

static switch_bool_t fifo_execute_sql_callback(switch_mutex_t *mutex, char *sql, switch_core_db_callback_func_t callback, void *pdata)
{
	switch_bool_t ret = SWITCH_FALSE;
	char *errmsg = NULL;
	switch_cache_db_handle_t *dbh = NULL;

	if (mutex) {
		switch_mutex_lock(mutex);
	}

	if (!(dbh = fifo_get_db_handle())) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error Opening DB\n");
		goto end;
	}

	switch_cache_db_execute_sql_callback(dbh, sql, callback, pdata, &errmsg);

	if (errmsg) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "SQL ERR: [%s] %s\n", sql, errmsg);
		free(errmsg);
	}

  end:

	switch_cache_db_release_db_handle(&dbh);

	if (mutex) {
		switch_mutex_unlock(mutex);
	}

	return ret;
}

static fifo_node_t *create_node(const char *name, uint32_t importance, switch_mutex_t *mutex)
{
	fifo_node_t *node;
	int x = 0;
	switch_memory_pool_t *pool;
	char outbound_count[80] = "";
	callback_t cbt = { 0 };
	char *sql = NULL;

	if (!globals.running) {
		return NULL;
	}

	switch_core_new_memory_pool(&pool);

	node = switch_core_alloc(pool, sizeof(*node));
	node->pool = pool;
	node->outbound_strategy = default_strategy;
	node->name = switch_core_strdup(node->pool, name);
	for (x = 0; x < MAX_PRI; x++) {
		fifo_queue_create(&node->fifo_list[x], SWITCH_CORE_QUEUE_LEN, node->pool);
		switch_assert(node->fifo_list[x]);
	}

	switch_core_hash_init(&node->consumer_hash, node->pool);
	switch_thread_rwlock_create(&node->rwlock, node->pool);
	switch_mutex_init(&node->mutex, SWITCH_MUTEX_NESTED, node->pool);
	cbt.buf = outbound_count;
	cbt.len = sizeof(outbound_count);
	sql = switch_mprintf("select count(*) from fifo_outbound where taking_calls = 1 and fifo_name = '%q'", name);
	fifo_execute_sql_callback(mutex, sql, sql2str_callback, &cbt);
	if (atoi(outbound_count) > 0) {
		node->has_outbound = 1;
	}
	switch_safe_free(sql);

	node->importance = importance;

	switch_mutex_lock(globals.mutex);
	switch_core_hash_insert(globals.fifo_hash, name, node);
	switch_mutex_unlock(globals.mutex);
	return node;
}

static int node_idle_consumers(fifo_node_t *node)
{
	switch_hash_index_t *hi;
	void *val;
	const void *var;
	switch_core_session_t *session;
	switch_channel_t *channel;
	int total = 0;

	switch_mutex_lock(node->mutex);
	for (hi = switch_hash_first(NULL, node->consumer_hash); hi; hi = switch_hash_next(hi)) {
		switch_hash_this(hi, &var, NULL, &val);
		session = (switch_core_session_t *) val;
		channel = switch_core_session_get_channel(session);
		if (!switch_channel_test_flag(channel, CF_BRIDGED)) {
			total++;
		}
	}
	switch_mutex_unlock(node->mutex);

	return total;

}

struct call_helper {
	char *uuid;
	char *node_name;
	char *originate_string;
	int timeout;
	switch_memory_pool_t *pool;
};

#define MAX_ROWS 2048
struct callback_helper {
	int need;
	switch_memory_pool_t *pool;
	struct call_helper *rows[MAX_ROWS];
	int rowcount;
};


static switch_status_t messagehook (switch_core_session_t *session, switch_core_session_message_t *msg)
{
	switch_event_t *event;
	switch_core_session_t *other_session, *caller_session, *consumer_session;
	switch_channel_t *channel, *other_channel, *caller_channel, *consumer_channel;
	const char *outbound_id;
	char *sql;

	switch (msg->message_id) {
    case SWITCH_MESSAGE_INDICATE_BRIDGE:
    case SWITCH_MESSAGE_INDICATE_UNBRIDGE:
        break;
    default:
        return SWITCH_STATUS_SUCCESS;
    }

	channel = switch_core_session_get_channel(session);
	outbound_id = switch_channel_get_variable(channel, "fifo_outbound_uuid");

	if ((other_session = switch_core_session_force_locate(msg->string_arg))) {
		
		other_channel = switch_core_session_get_channel(other_session);
		
		consumer_channel = channel;
		caller_channel = other_channel;
		
		consumer_session = session;
		caller_session = other_session;

	} else {
		return SWITCH_STATUS_SUCCESS;
	}


	switch (msg->message_id) {
	case SWITCH_MESSAGE_INDICATE_DISPLAY:
		sql = switch_mprintf("update fifo_bridge set caller_caller_id_name='%q', caller_caller_id_number='%q' where consumer_uuid='%q'",
							 switch_core_session_get_uuid(session));
		break;
	case SWITCH_MESSAGE_INDICATE_BRIDGE:
		{
			const char *col1 = NULL, *col2 = NULL;
			long epoch_start = 0;
			char date[80] = "";
			switch_time_t ts;
			switch_time_exp_t tm;
			switch_size_t retsize;
			const char *cid_name, *cid_number;

			if (switch_true(switch_channel_get_variable(channel, "fifo_bridged"))) {
				return SWITCH_STATUS_SUCCESS;
			}

			switch_process_import(consumer_session, caller_channel, "fifo_caller_consumer_import");
			switch_process_import(caller_session, consumer_channel, "fifo_consumer_caller_import");

			if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
				switch_channel_event_set_data(consumer_channel, event);
				switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", MANUAL_QUEUE_NAME);
				switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "bridge-consumer-start");
				switch_event_fire(&event);
			}

			if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
				switch_channel_event_set_data(other_channel, event);
				switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", MANUAL_QUEUE_NAME);
				switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "bridge-caller-start");
				switch_event_fire(&event);
			}
			
			cid_name = switch_channel_get_variable(consumer_channel, "callee_id_name");
			cid_number = switch_channel_get_variable(consumer_channel, "callee_id_number");

			if (zstr(cid_name)) {
				cid_name = cid_number;
			}

			if (zstr(cid_number)) {
				cid_name = switch_channel_get_variable(consumer_channel, "destination_number");
				cid_number = cid_name;
			}
			
			sql = switch_mprintf("insert into fifo_bridge "
								 "(fifo_name,caller_uuid,caller_caller_id_name,caller_caller_id_number,consumer_uuid,consumer_outgoing_uuid,bridge_start) "
								 "values ('%q','%q','%q','%q','%q','%q',%ld)",
								 MANUAL_QUEUE_NAME,
								 switch_core_session_get_uuid(other_session),
								 cid_name,
								 cid_number,
								 switch_core_session_get_uuid(session),
								 switch_str_nil(outbound_id),
								 (long) switch_epoch_time_now(NULL)
								 );
			
			fifo_execute_sql(sql, globals.sql_mutex);
			switch_safe_free(sql);

			if (switch_channel_direction(consumer_channel) == SWITCH_CALL_DIRECTION_OUTBOUND) {
				col1 = "manual_calls_in_count";
				col2 = "manual_calls_in_total_count";
			} else {
				col1 = "manual_calls_out_count";
				col2 = "manual_calls_out_total_count";
			}

			sql = switch_mprintf("update fifo_outbound set %s=%s+1,%s=%s+1 where uuid='%q'", col1, col1, col2, col2, outbound_id);
			fifo_execute_sql(sql, globals.sql_mutex);
			switch_safe_free(sql);
			

			epoch_start = (long)switch_epoch_time_now(NULL);

			ts = switch_micro_time_now();
			switch_time_exp_lt(&tm, ts);
			epoch_start = (long)switch_epoch_time_now(NULL);
			switch_strftime_nocheck(date, &retsize, sizeof(date), "%Y-%m-%d %T", &tm);
			switch_channel_set_variable(consumer_channel, "fifo_status", "TALKING");
			switch_channel_set_variable(consumer_channel, "fifo_target", switch_core_session_get_uuid(caller_session));
			switch_channel_set_variable(consumer_channel, "fifo_timestamp", date);
			switch_channel_set_variable_printf(consumer_channel, "fifo_epoch_start_bridge", "%ld", epoch_start);
			switch_channel_set_variable(consumer_channel, "fifo_role", "consumer");
			
			switch_channel_set_variable(caller_channel, "fifo_status", "TALKING");
			switch_channel_set_variable(caller_channel, "fifo_timestamp", date);
			switch_channel_set_variable_printf(caller_channel, "fifo_epoch_start_bridge", "%ld", epoch_start);
			switch_channel_set_variable(caller_channel, "fifo_target", switch_core_session_get_uuid(session));
			switch_channel_set_variable(caller_channel, "fifo_role", "caller");



			switch_channel_set_variable(consumer_channel, "fifo_role", "consumer");
			switch_channel_set_variable(caller_channel, "fifo_role", "caller");

			switch_channel_set_variable(consumer_channel, "fifo_bridged", "true");
			switch_channel_set_variable(consumer_channel, "fifo_manual_bridge", "true");

		}
		break;
	case SWITCH_MESSAGE_INDICATE_UNBRIDGE:
		{
			if (switch_true(switch_channel_get_variable(channel, "fifo_bridged"))) {
				char date[80] = "";
				switch_time_exp_t tm;
				switch_time_t ts = switch_micro_time_now();
				switch_size_t retsize;
				long epoch_start = 0, epoch_end = 0;
				const char *epoch_start_a = NULL;

				switch_channel_set_variable(channel, "fifo_bridged", NULL);
				
				ts = switch_micro_time_now();
				switch_time_exp_lt(&tm, ts);
				switch_strftime_nocheck(date, &retsize, sizeof(date), "%Y-%m-%d %T", &tm);
				
				sql = switch_mprintf("delete from fifo_bridge where consumer_uuid='%q'", switch_core_session_get_uuid(consumer_session));
				fifo_execute_sql(sql, globals.sql_mutex);
				switch_safe_free(sql);

				switch_channel_set_variable(consumer_channel, "fifo_status", "WAITING");
				switch_channel_set_variable(consumer_channel, "fifo_timestamp", date);
				
				switch_channel_set_variable(caller_channel, "fifo_status", "DONE");
				switch_channel_set_variable(caller_channel, "fifo_timestamp", date);

				if ((epoch_start_a = switch_channel_get_variable(consumer_channel, "fifo_epoch_start_bridge"))) {
					epoch_start = atol(epoch_start_a);
				}
				
				epoch_end = (long)switch_epoch_time_now(NULL);

				switch_channel_set_variable_printf(consumer_channel, "fifo_epoch_stop_bridge", "%ld", epoch_end);
				switch_channel_set_variable_printf(consumer_channel, "fifo_bridge_seconds", "%d", epoch_end - epoch_start);
				
				switch_channel_set_variable_printf(caller_channel, "fifo_epoch_stop_bridge", "%ld", epoch_end);
				switch_channel_set_variable_printf(caller_channel, "fifo_bridge_seconds", "%d", epoch_end - epoch_start);
				
				if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
					switch_channel_event_set_data(consumer_channel, event);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", MANUAL_QUEUE_NAME);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "bridge-consumer-stop");
					switch_event_fire(&event);
				}

				if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
					switch_channel_event_set_data(caller_channel, event);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", MANUAL_QUEUE_NAME);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "bridge-caller-stop");
					switch_event_fire(&event);
				}

				if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
					switch_channel_event_set_data(consumer_channel, event);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", MANUAL_QUEUE_NAME);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "consumer_stop");
					switch_event_fire(&event);
				}
			}
			
		}
		break;
	default:
		break;
	}

	if (other_session) {
		switch_core_session_rwunlock(other_session);
	}

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t hanguphook(switch_core_session_t *session)
{
    switch_channel_t *channel = switch_core_session_get_channel(session);
    switch_channel_state_t state = switch_channel_get_state(channel);
    const char *uuid = NULL;
    char sql[512] = "";
	switch_core_session_message_t msg = { 0 };

    if (state == CS_HANGUP || state == CS_ROUTING) {
        if ((uuid = switch_channel_get_variable(channel, "fifo_outbound_uuid"))) {
			if ((switch_true(switch_channel_get_variable(channel, "fifo_manual_bridge")))) {
				switch_snprintf(sql, sizeof(sql), "update fifo_outbound set use_count=use_count-1, "
								"next_avail=%ld + lag where uuid='%s' and use_count > 0",
								(long)switch_epoch_time_now(NULL), uuid);
			} else {

				switch_snprintf(sql, sizeof(sql), "update fifo_outbound set use_count=use_count-1, "
								"outbound_call_count=outbound_call_count+1, "
								"outbound_call_total_count=outbound_call_total_count+1, next_avail=%ld + lag where uuid='%s' and use_count > 0",
								(long)switch_epoch_time_now(NULL), uuid);
			}

            fifo_execute_sql(sql, globals.sql_mutex);
        }
        switch_core_event_hook_remove_state_change(session, hanguphook);
        switch_core_event_hook_remove_receive_message(session, messagehook);

		if (switch_true(switch_channel_get_variable(channel, "fifo_bridged"))) {
			msg.message_id = SWITCH_MESSAGE_INDICATE_UNBRIDGE;
			msg.from = __FILE__;
			msg.string_arg = switch_channel_get_variable(channel, SWITCH_SIGNAL_BOND_VARIABLE);
			
			if (msg.string_arg && switch_ivr_uuid_exists(msg.string_arg)) {
				messagehook(session, &msg);
			}
		}


    }
    return SWITCH_STATUS_SUCCESS;
}


static void *SWITCH_THREAD_FUNC ringall_thread_run(switch_thread_t *thread, void *obj)
{
	struct callback_helper *cbh = (struct callback_helper *) obj;
	char *node_name;
	int i = 0;
	int timeout = 0;
	switch_stream_handle_t stream = { 0 };
	fifo_node_t *node = NULL;
	char *originate_string = NULL;
	switch_event_t *ovars = NULL;
	switch_status_t status;
	switch_core_session_t *session = NULL;
	switch_call_cause_t cause = SWITCH_CAUSE_NONE;
	char *app_name = NULL, *arg = NULL;
	switch_caller_extension_t *extension = NULL;
	switch_channel_t *channel;
	char *caller_id_name = NULL, *cid_num = NULL, *id = NULL;
	switch_event_t *pop = NULL, *pop_dup = NULL;
	fifo_queue_t *q = NULL;
	int x = 0;
	switch_event_t *event;
	switch_uuid_t uuid;
    char uuid_str[SWITCH_UUID_FORMATTED_LENGTH + 1];

    switch_uuid_get(&uuid);
    switch_uuid_format(uuid_str, &uuid);
	
	if (!cbh->rowcount) {
		goto end;
	}

	node_name = cbh->rows[0]->node_name;

	switch_mutex_lock(globals.mutex);
	node = switch_core_hash_find(globals.fifo_hash, node_name);
	switch_mutex_unlock(globals.mutex);

	if (node) {
		switch_mutex_lock(node->mutex);
		node->busy++;
		node->ring_consumer_count = cbh->rowcount;
		switch_mutex_unlock(node->mutex);
	} else {
		goto end;
	}

	SWITCH_STANDARD_STREAM(stream);

	switch_event_create(&ovars, SWITCH_EVENT_REQUEST_PARAMS);
	switch_assert(ovars);

	
	for (i = 0; i < cbh->rowcount; i++) {
		struct call_helper *h = cbh->rows[i];
		char *parsed = NULL;

		switch_event_create_brackets(h->originate_string, '{', '}', ',', &ovars, &parsed);
		switch_event_del_header(ovars, "fifo_outbound_uuid");
		
		if (!h->timeout) h->timeout = 60;
		if (timeout < h->timeout) timeout = h->timeout;
		
		stream.write_function(&stream, "[leg_timeout=%d,fifo_outbound_uuid=%s]%s,", h->timeout, h->uuid, parsed ? parsed : h->originate_string);
		switch_safe_free(parsed);
		
	}
	

	originate_string = (char *) stream.data;

	if (originate_string) {
		end_of(originate_string) = '\0';
	}
	
	if (!timeout) timeout = 60;
	
	pop = pop_dup = NULL;

	for (x = 0; x < MAX_PRI; x++) {
		q = node->fifo_list[x];
		if (fifo_queue_pop_nameval(q, "variable_fifo_vip", "true", &pop_dup, SWITCH_FALSE) == SWITCH_STATUS_SUCCESS && pop_dup) {
			pop = pop_dup;
			break;
		}
	}

	if (!pop) {
		for (x = 0; x < MAX_PRI; x++) {
			q = node->fifo_list[x];
			if (fifo_queue_pop(node->fifo_list[x], &pop_dup, SWITCH_FALSE) == SWITCH_STATUS_SUCCESS && pop_dup) {
				pop = pop_dup;
				break;
			}
		}
	}

	if (!pop) {
		goto end;
	}
	
	if (!switch_event_get_header(ovars, "origination_caller_id_name")) {
		if ((caller_id_name = switch_event_get_header(pop, "caller-caller-id-name"))) {
			if (!zstr(node->outbound_name)) {
				switch_event_add_header(ovars, SWITCH_STACK_BOTTOM, "origination_caller_id_name", "(%s) %s", node->outbound_name, caller_id_name);
			} else {
				switch_event_add_header_string(ovars, SWITCH_STACK_BOTTOM, "origination_caller_id_name", caller_id_name);
			}
		}
	}

	if (!switch_event_get_header(ovars, "origination_caller_id_number")) {
		if ((cid_num = switch_event_get_header(pop, "caller-caller-id-number"))) {
			switch_event_add_header_string(ovars, SWITCH_STACK_BOTTOM, "origination_caller_id_number", cid_num);
		}
	}
	
	if ((id = switch_event_get_header(pop, "unique-id"))) {
		switch_event_add_header_string(ovars, SWITCH_STACK_BOTTOM, "fifo_bridge_uuid", id);
	}

	switch_event_add_header_string(ovars, SWITCH_STACK_BOTTOM, "fifo_originate_uuid", uuid_str);

	if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
		switch_core_session_t *session;
		if (id && (session = switch_core_session_locate(id))) {
			switch_channel_t *channel = switch_core_session_get_channel(session);

			switch_channel_set_variable(channel, "fifo_originate_uuid", uuid_str);
			switch_channel_event_set_data(channel, event);
			switch_core_session_rwunlock(session);
		}

		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", node->name);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "pre-dial");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "outbound-strategy", "ringall");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "caller-uuid", id);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "originate_string", originate_string);

		for (i = 0; i < cbh->rowcount; i++) {
			struct call_helper *h = cbh->rows[i];
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Outbound-UUID", h->uuid);
		}

		switch_event_fire(&event);
	}

	for (i = 0; i < cbh->rowcount; i++) {
		struct call_helper *h = cbh->rows[i];
		char *sql = switch_mprintf("update fifo_outbound set use_count=use_count+1 where uuid='%s'", h->uuid);
		
		fifo_execute_sql(sql, globals.sql_mutex);
		switch_safe_free(sql);
		
	}

	status = switch_ivr_originate(NULL, &session, &cause, originate_string, timeout, NULL, NULL, NULL, NULL, ovars, SOF_NONE, NULL);
	
	if (status != SWITCH_STATUS_SUCCESS) {
		for (i = 0; i < cbh->rowcount; i++) {
			struct call_helper *h = cbh->rows[i];
			char *sql = switch_mprintf("update fifo_outbound set use_count=use_count-1, "
									   "outbound_fail_count=outbound_fail_count+1, next_avail=%ld + lag where uuid='%q' and use_count > 0",
									   (long) switch_epoch_time_now(NULL), h->uuid);
			fifo_execute_sql(sql, globals.sql_mutex);
			switch_safe_free(sql);

		}
		
		if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", node->name);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "post-dial");
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "outbound-strategy", "ringall");
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "caller-uuid", id);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "result", "failure");
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "cause", switch_channel_cause2str(cause));
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "originate_string", originate_string);
			switch_event_fire(&event);
		}
		goto end;
	}

	channel = switch_core_session_get_channel(session);

	if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
		switch_channel_event_set_data(channel, event);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", node->name);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "post-dial");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "outbound-strategy", "ringall");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "caller-uuid", id);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Outbound-UUID", switch_channel_get_variable(channel, "fifo_outbound_uuid"));
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "result", "success");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "originate_string", originate_string);
		switch_event_fire(&event);
	}


	switch_channel_set_variable(channel, "fifo_pop_order", NULL);
	switch_core_event_hook_add_state_change(session, hanguphook);

	app_name = "fifo";
	arg = switch_core_session_sprintf(session, "%s out nowait", node_name);
	extension = switch_caller_extension_new(session, app_name, arg);
	switch_caller_extension_add_application(session, extension, app_name, arg);
	switch_channel_set_caller_extension(channel, extension);
	switch_channel_set_state(channel, CS_EXECUTE);
	switch_core_session_rwunlock(session);

  end:

	switch_safe_free(originate_string);

	switch_event_destroy(&ovars);

	if (pop_dup) {
		switch_event_destroy(&pop_dup);
	}

	if (node) {
		switch_mutex_lock(node->mutex);
		node->ring_consumer_count = 0;
		if (node->busy) node->busy--;
		switch_mutex_unlock(node->mutex);
	}

	switch_core_destroy_memory_pool(&cbh->pool);

	return NULL;
}

static void *SWITCH_THREAD_FUNC o_thread_run(switch_thread_t *thread, void *obj)
{
	struct call_helper *h = (struct call_helper *) obj;

	switch_core_session_t *session = NULL;
	switch_channel_t *channel;
	switch_call_cause_t cause = SWITCH_CAUSE_NONE;
	switch_caller_extension_t *extension = NULL;
	char *app_name, *arg = NULL, *originate_string = NULL;
	const char *member_wait = NULL;
	fifo_node_t *node = NULL;
	switch_event_t *ovars = NULL;
	switch_status_t status = SWITCH_STATUS_FALSE;
	switch_event_t *event = NULL;
	char *sql = NULL;

	switch_mutex_lock(globals.mutex);
	node = switch_core_hash_find(globals.fifo_hash, h->node_name);
	switch_mutex_unlock(globals.mutex);

	if (node) {
		switch_mutex_lock(node->mutex);
		node->ring_consumer_count++;
		node->busy++;
		switch_mutex_unlock(node->mutex);
	}

	switch_event_create(&ovars, SWITCH_EVENT_REQUEST_PARAMS);
	switch_assert(ovars);
	switch_event_add_header(ovars, SWITCH_STACK_BOTTOM, "originate_timeout", "%d", h->timeout);

	if (switch_stristr("origination_caller", h->originate_string)) {
		originate_string = switch_mprintf("{execute_on_answer='unset fifo_hangup_check',fifo_hangup_check='%q'}%s",
										  node->name, h->originate_string);
	} else {
		if (!zstr(node->outbound_name)) {
			originate_string = switch_mprintf("{execute_on_answer='unset fifo_hangup_check',fifo_hangup_check='%q',"
											  "origination_caller_id_name=Queue,origination_caller_id_number='Queue: %q'}%s",
											  node->name,  node->outbound_name, h->originate_string);
		} else {
			originate_string = switch_mprintf("{execute_on_answer='unset fifo_hangup_check',fifo_hangup_check='%q',"
											  "origination_caller_id_name=Queue,origination_caller_id_number='Queue: %q'}%s",
											  node->name,  node->name, h->originate_string);
		}
			
	}

	if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", node->name);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "pre-dial");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Outbound-UUID", h->uuid);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "outbound-strategy", "enterprise");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "originate_string", originate_string);
		switch_event_fire(&event);
	}

	
	sql = switch_mprintf("update fifo_outbound set use_count=use_count+1 where uuid='%s'", h->uuid);
	fifo_execute_sql(sql, globals.sql_mutex);
	switch_safe_free(sql);


	status = switch_ivr_originate(NULL, &session, &cause, originate_string, h->timeout, NULL, NULL, NULL, NULL, ovars, SOF_NONE, NULL);
	free(originate_string);


	if (status != SWITCH_STATUS_SUCCESS) {

		sql = switch_mprintf("update fifo_outbound set use_count=use_count-1, "
							 "outbound_fail_count=outbound_fail_count+1, next_avail=%ld + lag where uuid='%q' and use_count > 0",
							 (long) switch_epoch_time_now(NULL), h->uuid);
		fifo_execute_sql(sql, globals.sql_mutex);
		switch_safe_free(sql);
		
		if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", node->name);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "post-dial");
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Outbound-UUID", h->uuid);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "outbound-strategy", "enterprise");
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "result", "failure");
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "cause", switch_channel_cause2str(cause));
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "originate_string", originate_string);
			switch_event_fire(&event);
		}

		goto end;
	}

	channel = switch_core_session_get_channel(session);

	if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
		switch_channel_event_set_data(channel, event);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", node->name);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "post-dial");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Outbound-UUID", h->uuid);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "outbound-strategy", "enterprise");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "result", "success");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "originate_string", originate_string);
		switch_event_fire(&event);
	}


	if ((member_wait = switch_channel_get_variable(channel, "fifo_member_wait")) || (member_wait = switch_channel_get_variable(channel, "member_wait"))) {
		if (strcasecmp(member_wait, "wait") && strcasecmp(member_wait, "nowait")) {
			member_wait = NULL;
		}
	}

	switch_core_event_hook_add_state_change(session, hanguphook);
	switch_channel_set_variable(channel, "fifo_outbound_uuid", h->uuid);
	app_name = "fifo";
	arg = switch_core_session_sprintf(session, "%s out %s", h->node_name, member_wait ? member_wait : "wait");
	extension = switch_caller_extension_new(session, app_name, arg);
	switch_caller_extension_add_application(session, extension, app_name, arg);
	switch_channel_set_caller_extension(channel, extension);
	switch_channel_set_state(channel, CS_EXECUTE);
	switch_core_session_rwunlock(session);

  end:

	switch_event_destroy(&ovars);
	if (node) {
		switch_mutex_lock(node->mutex);
		if (node->ring_consumer_count-- < 0) {
			node->ring_consumer_count = 0;
		}
		if (node->busy) node->busy--;
		switch_mutex_unlock(node->mutex);
	}
	switch_core_destroy_memory_pool(&h->pool);

	return NULL;
}

static int place_call_ringall_callback(void *pArg, int argc, char **argv, char **columnNames)
{
	struct callback_helper *cbh = (struct callback_helper *) pArg;
	struct call_helper *h;

	h = switch_core_alloc(cbh->pool, sizeof(*h));
	h->pool = cbh->pool;
	h->uuid = switch_core_strdup(h->pool, argv[0]);
	h->node_name = switch_core_strdup(h->pool, argv[1]);
	h->originate_string = switch_core_strdup(h->pool, argv[2]);
	h->timeout = atoi(argv[5]);
	
	cbh->rows[cbh->rowcount++] = h;

	if (cbh->rowcount == MAX_ROWS) return -1;

	if (cbh->need) {
		cbh->need--;
		return cbh->need ? 0 : -1;
	}

	return 0;
	
}

static int place_call_enterprise_callback(void *pArg, int argc, char **argv, char **columnNames)
{

	int *need = (int *) pArg;

	switch_thread_t *thread;
	switch_threadattr_t *thd_attr = NULL;
	switch_memory_pool_t *pool;
	struct call_helper *h;

	switch_core_new_memory_pool(&pool);
	h = switch_core_alloc(pool, sizeof(*h));
	h->pool = pool;
	h->uuid = switch_core_strdup(h->pool, argv[0]);
	h->node_name = switch_core_strdup(h->pool, argv[1]);
	h->originate_string = switch_core_strdup(h->pool, argv[2]);
	h->timeout = atoi(argv[5]);


	switch_threadattr_create(&thd_attr, h->pool);
	switch_threadattr_detach_set(thd_attr, 1);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&thread, thd_attr, o_thread_run, h, h->pool);

	(*need)--;

	return *need ? 0 : -1;
}

static void find_consumers(fifo_node_t *node)
{
	char *sql;


	sql = switch_mprintf("select uuid, fifo_name, originate_string, simo_count, use_count, timeout, lag, "
						 "next_avail, expires, static, outbound_call_count, outbound_fail_count, hostname "
						 "from fifo_outbound "
						 "where taking_calls = 1 and (fifo_name = '%q') and (use_count < simo_count) and (next_avail = 0 or next_avail <= %ld) "
						 "order by next_avail, outbound_fail_count, outbound_call_count",
						 node->name, (long) switch_epoch_time_now(NULL)
						 );
	
	

	switch(node->outbound_strategy) {
	case NODE_STRATEGY_ENTERPRISE:
		{
			int need = node_consumer_wait_count(node);

			if (node->outbound_per_cycle && node->outbound_per_cycle < need) {
				need = node->outbound_per_cycle;
			}

			fifo_execute_sql_callback(globals.sql_mutex, sql, place_call_enterprise_callback, &need);

		}
		break;
	case NODE_STRATEGY_RINGALL:
		{
			switch_thread_t *thread;
			switch_threadattr_t *thd_attr = NULL;
			struct callback_helper *cbh;
			switch_memory_pool_t *pool;
			
			switch_core_new_memory_pool(&pool);
			cbh = switch_core_alloc(pool, sizeof(*cbh));
			cbh->pool = pool;
			cbh->need = 1;

			if (node->outbound_per_cycle != cbh->need) {
				cbh->need = node->outbound_per_cycle;
			}

			fifo_execute_sql_callback(globals.sql_mutex, sql, place_call_ringall_callback, cbh);

			if (cbh->rowcount) {
				switch_threadattr_create(&thd_attr, cbh->pool);
				switch_threadattr_detach_set(thd_attr, 1);
				switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
				switch_thread_create(&thread, thd_attr, ringall_thread_run, cbh, cbh->pool);
			}

		}
		break;
	default:
		break;
	}


	switch_safe_free(sql);
}

static void *SWITCH_THREAD_FUNC node_thread_run(switch_thread_t *thread, void *obj)
{
	fifo_node_t *node;

	globals.node_thread_running = 1;

	while (globals.node_thread_running == 1) {
		switch_hash_index_t *hi;
		void *val;
		const void *var;
		int ppl_waiting, consumer_total, idle_consumers;

		switch_mutex_lock(globals.mutex);
		for (hi = switch_hash_first(NULL, globals.fifo_hash); hi; hi = switch_hash_next(hi)) {
			switch_hash_this(hi, &var, NULL, &val);
			if ((node = (fifo_node_t *) val)) {
				if (node->has_outbound && node->ready && !node->busy) {
					switch_mutex_lock(node->mutex);
					ppl_waiting = node_consumer_wait_count(node);
					consumer_total = node->consumer_count;
					idle_consumers = node_idle_consumers(node);

					/* switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
					   "%s waiting %d consumer_total %d idle_consumers %d ring_consumers %d\n", node->name, ppl_waiting, consumer_total, idle_consumers, node->ring_consumer_count); */

					if ((ppl_waiting - node->ring_consumer_count > 0) && (!consumer_total || !idle_consumers)) {
						find_consumers(node);
					}
					switch_mutex_unlock(node->mutex);
				}
			}
		}
		switch_mutex_unlock(globals.mutex);

		switch_yield(1000000);
	}

	globals.node_thread_running = 0;

	return NULL;
}

static void start_node_thread(switch_memory_pool_t *pool)
{
	switch_thread_t *thread;
	switch_threadattr_t *thd_attr = NULL;

	switch_threadattr_create(&thd_attr, pool);
	switch_threadattr_detach_set(thd_attr, 1);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&thread, thd_attr, node_thread_run, pool, pool);
}

static int stop_node_thread(void)
{
	int sanity = 20;

	if (globals.node_thread_running) {
		globals.node_thread_running = -1;
		while (globals.node_thread_running) {
			switch_yield(500000);
			if (!--sanity) {
				return -1;
			}
		}
	}

	return 0;
}

static void check_ocancel(switch_core_session_t *session)
{
	switch_channel_t *channel;
	const char *var;

	switch_assert(session);

	channel = switch_core_session_get_channel(session);

	if (!switch_channel_test_flag(channel, CF_TRANSFER) && (var = switch_channel_get_variable(channel, "fifo_originate_uuid"))) {
		switch_core_session_hupall_matching_var("fifo_originate_uuid", var, 
												switch_channel_test_flag(channel, CF_ANSWERED) ? 
												SWITCH_CAUSE_NORMAL_CLEARING : SWITCH_CAUSE_ORIGINATOR_CANCEL);
	}
}


static void check_cancel(fifo_node_t *node)
{
	int ppl_waiting = node_consumer_wait_count(node);

	if (node->ring_consumer_count > 0 && ppl_waiting < 1) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Outbound call count (%d) exceeds required value for queue %s (%d), "
						  "Ending extraneous calls\n", node->ring_consumer_count, node->name, ppl_waiting);

		
		switch_core_session_hupall_matching_var("fifo_hangup_check", node->name, SWITCH_CAUSE_ORIGINATOR_CANCEL);
	}
}

static void send_presence(fifo_node_t *node)
{
	switch_event_t *event;
	int wait_count = 0;

	if (!globals.running) {
		return;
	}

	if (switch_event_create(&event, SWITCH_EVENT_PRESENCE_IN) == SWITCH_STATUS_SUCCESS) {
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "proto", "park");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "login", node->name);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "from", node->name);
		if ((wait_count = node_consumer_wait_count(node)) > 0) {
			switch_event_add_header(event, SWITCH_STACK_BOTTOM, "status", "Active (%d waiting)", wait_count);
		} else {
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "status", "Idle");
		}
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "rpid", "unknown");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "event_type", "presence");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "alt_event_type", "dialog");
		switch_event_add_header(event, SWITCH_STACK_BOTTOM, "event_count", "%d", 0);

		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "channel-state", wait_count > 0 ? "CS_ROUTING" : "CS_HANGUP");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "unique-id", node->name);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "answer-state", wait_count > 0 ? "early" : "terminated");
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "presence-call-direction", "inbound");
		switch_event_fire(&event);
	}
}

static void pres_event_handler(switch_event_t *event)
{
	char *to = switch_event_get_header(event, "to");
	char *dup_to = NULL, *node_name;
	fifo_node_t *node;

	if (!globals.running) {
		return;
	}

	if (!to || strncasecmp(to, "park+", 5)) {
		return;
	}

	dup_to = strdup(to);
	switch_assert(dup_to);

	node_name = dup_to + 5;

	switch_mutex_lock(globals.mutex);
	if (!(node = switch_core_hash_find(globals.fifo_hash, node_name))) {
		node = create_node(node_name, 0, globals.sql_mutex);
		node->ready = 1;
	}

	send_presence(node);

	switch_mutex_unlock(globals.mutex);

	switch_safe_free(dup_to);
}

static uint32_t fifo_add_outbound(const char *node_name, const char *url, uint32_t priority)
{
	fifo_node_t *node;
	switch_event_t *call_event;

	if (priority >= MAX_PRI) {
		priority = MAX_PRI - 1;
	}

	switch_mutex_lock(globals.mutex);

	if (!(node = switch_core_hash_find(globals.fifo_hash, node_name))) {
		node = create_node(node_name, 0, globals.sql_mutex);
	}

	switch_mutex_unlock(globals.mutex);

	switch_event_create(&call_event, SWITCH_EVENT_CHANNEL_DATA);
	switch_event_add_header_string(call_event, SWITCH_STACK_BOTTOM, "dial-url", url);
	
	fifo_queue_push(node->fifo_list[priority], call_event);
	call_event = NULL;

	return fifo_queue_size(node->fifo_list[priority]);

}


SWITCH_STANDARD_API(fifo_add_outbound_function)
{
	char *data = NULL, *argv[4] = { 0 };
	int argc;
	uint32_t priority = 0;

	if (zstr(cmd)) {
		goto fail;
	}

	data = strdup(cmd);

	if ((argc = switch_separate_string(data, ' ', argv, (sizeof(argv) / sizeof(argv[0])))) < 2 || !argv[0]) {
		goto fail;
	}

	if (argv[2]) {
		int tmp = atoi(argv[2]);
		if (tmp > 0) {
			priority = tmp;
		}
	}

	stream->write_function(stream, "%d", fifo_add_outbound(argv[0], argv[1], priority));


	free(data);
	return SWITCH_STATUS_SUCCESS;


  fail:

	free(data);
	stream->write_function(stream, "0");
	return SWITCH_STATUS_SUCCESS;

}

SWITCH_STANDARD_APP(fifo_member_usage_function)
{
	char *sql;
	switch_channel_t *channel = switch_core_session_get_channel(session);

	if (zstr(data)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid!\n");
		return;
	}

	switch_channel_set_variable(channel, "fifo_outbound_uuid", data);
	sql = switch_mprintf("update fifo_outbound set use_count=use_count+1,outbound_fail_count=0 where uuid='%s'", data);
	
	fifo_execute_sql(sql, globals.sql_mutex);
	switch_safe_free(sql);
	switch_core_event_hook_add_receive_message(session, messagehook);
	switch_core_event_hook_add_state_change(session, hanguphook);

}

typedef enum {
	STRAT_MORE_PPL,
	STRAT_WAITING_LONGER,
} fifo_strategy_t;

#define MAX_NODES_PER_CONSUMER 25
#define FIFO_DESC "Fifo for stacking parked calls."
#define FIFO_USAGE "<fifo name>[!<importance_number>] [in [<announce file>|undef] [<music file>|undef] | out [wait|nowait] [<announce file>|undef] [<music file>|undef]]"
SWITCH_STANDARD_APP(fifo_function)
{
	int argc;
	char *mydata = NULL, *argv[5] = { 0 };
	fifo_node_t *node = NULL, *node_list[MAX_NODES_PER_CONSUMER + 1] = { 0 };
	switch_channel_t *channel = switch_core_session_get_channel(session);
	int do_wait = 1, node_count = 0, i = 0;
	const char *moh = NULL;
	const char *announce = NULL;
	switch_event_t *event = NULL;
	char date[80] = "";
	switch_time_exp_t tm;
	switch_time_t ts = switch_micro_time_now();
	switch_size_t retsize;
	char *list_string;
	int nlist_count;
	char *nlist[MAX_NODES_PER_CONSUMER];
	int consumer = 0;
	const char *arg_fifo_name = NULL;
	const char *arg_inout = NULL;
	const char *serviced_uuid = NULL;

	if (!globals.running) {
		return;
	}

	if (zstr(data)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "No Args\n");
		return;
	}

	switch_channel_set_variable(channel, "fifo_hangup_check", NULL);

	mydata = switch_core_session_strdup(session, data);
	switch_assert(mydata);

	argc = switch_separate_string(mydata, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
	arg_fifo_name = argv[0];
	arg_inout = argv[1];

	if (!(arg_fifo_name && arg_inout)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "USAGE %s\n", FIFO_USAGE);
		return;
	}

	if (!strcasecmp(arg_inout, "out")) {
		consumer = 1;
	} else if (strcasecmp(arg_inout, "in")) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "USAGE %s\n", FIFO_USAGE);
		return;
	}

	list_string = switch_core_session_strdup(session, arg_fifo_name);

	if (!(nlist_count = switch_separate_string(list_string, ',', nlist, (sizeof(nlist) / sizeof(nlist[0]))))) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "USAGE %s\n", FIFO_USAGE);
		return;
	}

	if (!consumer && nlist_count > 1) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "USAGE %s\n", FIFO_USAGE);
		return;
	}

	switch_mutex_lock(globals.mutex);
	for (i = 0; i < nlist_count; i++) {
		int importance = 0;
		char *p;

		if ((p = strrchr(nlist[i], '!'))) {
			*p++ = '\0';
			importance = atoi(p);
			if (importance < 0) {
				importance = 0;
			}
		}


		if (!(node = switch_core_hash_find(globals.fifo_hash, nlist[i]))) {
			node = create_node(nlist[i], importance, globals.sql_mutex);
			node->ready = 1;
		}
		node_list[node_count++] = node;
	}

	if (switch_true(switch_channel_get_variable(channel, "fifo_destroy_after_use")) && node->ready == 1) {
		node->ready = FIFO_DELAY_DESTROY;
	}

	switch_mutex_unlock(globals.mutex);

	moh = switch_channel_get_variable(channel, "fifo_music");
	announce = switch_channel_get_variable(channel, "fifo_announce");

	if (consumer) {
		if (argc > 3) {
			announce = argv[3];
		}

		if (argc > 4) {
			moh = argv[4];
		}
	} else {
		if (argc > 2) {
			announce = argv[2];
		}

		if (argc > 3) {
			moh = argv[3];
		}
	}

	if (moh && !strcasecmp(moh, "silence")) {
		moh = NULL;
	}

	check_string(announce);
	check_string(moh);
	switch_assert(node);

	switch_core_media_bug_pause(session);

	if (!consumer) {
		switch_core_session_t *other_session;
		switch_channel_t *other_channel;
		const char *uuid = switch_core_session_get_uuid(session);
		const char *pri;
		char tmp[25] = "";
		int p = 0;
		int aborted = 0;
		fifo_chime_data_t cd = { {0} };
		const char *chime_list = switch_channel_get_variable(channel, "fifo_chime_list");
		const char *chime_freq = switch_channel_get_variable(channel, "fifo_chime_freq");
		const char *orbit_exten = switch_channel_get_variable(channel, "fifo_orbit_exten");
		const char *orbit_dialplan = switch_channel_get_variable(channel, "fifo_orbit_dialplan");
		const char *orbit_context = switch_channel_get_variable(channel, "fifo_orbit_context");

		const char *orbit_ann = switch_channel_get_variable(channel, "fifo_orbit_announce");
		const char *caller_exit_key = switch_channel_get_variable(channel, "fifo_caller_exit_key");
		int freq = 30;
		int ftmp = 0;
		int to = 60;
		switch_event_t *call_event;

		if (orbit_exten) {
			char *ot;
			if ((cd.orbit_exten = switch_core_session_strdup(session, orbit_exten))) {
				if ((ot = strchr(cd.orbit_exten, ':'))) {
					*ot++ = '\0';
					if ((to = atoi(ot)) < 0) {
						to = 60;
					}
				}
				cd.orbit_timeout = switch_epoch_time_now(NULL) + to;
			}
			cd.orbit_dialplan = switch_core_session_strdup(session, orbit_dialplan);
			cd.orbit_context = switch_core_session_strdup(session, orbit_context);
		}

		if (chime_freq) {
			ftmp = atoi(chime_freq);
			if (ftmp > 0) {
				freq = ftmp;
			}
		}

		switch_channel_answer(channel);

		switch_mutex_lock(node->mutex);
		node->caller_count++;

		if ((pri = switch_channel_get_variable(channel, "fifo_priority"))) {
			p = atoi(pri);
		}

		if (p >= MAX_PRI) {
			p = MAX_PRI - 1;
		}

		if (!node_consumer_wait_count(node)) {
			node->start_waiting = switch_micro_time_now();
		}

		if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
			switch_channel_event_set_data(channel, event);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", argv[0]);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "push");
			switch_event_add_header(event, SWITCH_STACK_BOTTOM, "FIFO-Slot", "%d", p);
			switch_event_fire(&event);
		}

		switch_event_create(&call_event, SWITCH_EVENT_CHANNEL_DATA);
		switch_channel_event_set_data(channel, call_event);
		

		fifo_queue_push(node->fifo_list[p], call_event);
		call_event = NULL;
		switch_snprintf(tmp, sizeof(tmp), "%d", fifo_queue_size(node->fifo_list[p]));
		switch_channel_set_variable(channel, "fifo_position", tmp);

		if (!pri) {
			switch_snprintf(tmp, sizeof(tmp), "%d", p);
			switch_channel_set_variable(channel, "fifo_priority", tmp);
		}

		switch_mutex_unlock(node->mutex);

		ts = switch_micro_time_now();
		switch_time_exp_lt(&tm, ts);
		switch_strftime_nocheck(date, &retsize, sizeof(date), "%Y-%m-%d %T", &tm);
		switch_channel_set_variable(channel, "fifo_status", "WAITING");
		switch_channel_set_variable(channel, "fifo_timestamp", date);
		switch_channel_set_variable(channel, "fifo_serviced_uuid", NULL);

		switch_channel_set_app_flag(channel, CF_APP_TAGGED);

		if (chime_list) {
			char *list_dup = switch_core_session_strdup(session, chime_list);
			cd.total = switch_separate_string(list_dup, ',', cd.list, (sizeof(cd.list) / sizeof(cd.list[0])));
			cd.freq = freq;
			cd.next = switch_epoch_time_now(NULL) + cd.freq;
		}

		send_presence(node);

		while (switch_channel_ready(channel)) {
			switch_input_args_t args = { 0 };
			char buf[25] = "";

			args.input_callback = moh_on_dtmf;
			args.buf = buf;
			args.buflen = sizeof(buf);

			if (cd.total || cd.orbit_timeout) {
				args.read_frame_callback = caller_read_frame_callback;
				args.user_data = &cd;
			}

			if (cd.abort || cd.do_orbit) {
				aborted = 1;
				goto abort;
			}

			if ((serviced_uuid = switch_channel_get_variable(channel, "fifo_serviced_uuid"))) {
				break;
			}

			switch_core_session_flush_private_events(session);

			if (moh) {
				switch_status_t status = switch_ivr_play_file(session, NULL, moh, &args);
				if (!SWITCH_READ_ACCEPTABLE(status)) {
					aborted = 1;
					goto abort;
				}
			} else {
				switch_ivr_collect_digits_callback(session, &args, 0, 0);
			}

			if (match_key(caller_exit_key, *buf)) {
				switch_channel_set_variable(channel, "fifo_caller_exit_key", (char *)buf);
				aborted = 1;
				goto abort;
			}

		}

		if (!serviced_uuid && switch_channel_ready(channel)) {
			switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
		} else if ((other_session = switch_core_session_locate(serviced_uuid))) {
			int ready;
			other_channel = switch_core_session_get_channel(other_session);
			ready = switch_channel_ready(other_channel);
			switch_core_session_rwunlock(other_session);
			if (!ready) {
				switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
			}
		}

		switch_core_session_flush_private_events(session);

		if (switch_channel_ready(channel)) {
			if (announce) {
				switch_ivr_play_file(session, NULL, announce, NULL);
			}
		}

		switch_channel_clear_app_flag(channel, CF_APP_TAGGED);

	  abort:

		if (!aborted && switch_channel_ready(channel)) {
			switch_channel_set_state(channel, CS_HIBERNATE);
			goto done;
		} else {
			ts = switch_micro_time_now();
			switch_time_exp_lt(&tm, ts);
			switch_strftime_nocheck(date, &retsize, sizeof(date), "%Y-%m-%d %T", &tm);
			switch_channel_set_variable(channel, "fifo_status", cd.do_orbit ? "TIMEOUT" : "ABORTED");
			switch_channel_set_variable(channel, "fifo_timestamp", date);

			if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
				switch_channel_event_set_data(channel, event);
				switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", argv[0]);
				switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", cd.do_orbit ? "timeout" : "abort");
				switch_event_fire(&event);
			}

			switch_mutex_lock(globals.mutex);
			switch_mutex_lock(node->mutex);
			node_remove_uuid(node, uuid);
			node->caller_count--;
			switch_mutex_unlock(node->mutex);
			send_presence(node);
			check_cancel(node);
			switch_mutex_unlock(globals.mutex);

		}

		if ((switch_true(switch_channel_get_variable(channel, "fifo_caller_exit_to_orbit")) || cd.do_orbit) && cd.orbit_exten) {
			if (orbit_ann) {
				switch_ivr_play_file(session, NULL, orbit_ann, NULL);
			}
			switch_ivr_session_transfer(session, cd.orbit_exten, cd.orbit_dialplan, cd.orbit_context);
		}

		check_ocancel(session);

		goto done;

	} else {					/* consumer */
		switch_event_t *pop = NULL;
		switch_frame_t *read_frame;
		switch_status_t status;
		switch_core_session_t *other_session;
		switch_input_args_t args = { 0 };
		const char *pop_order = NULL;
		int custom_pop = 0;
		int pop_array[MAX_PRI] = { 0 };
		char *pop_list[MAX_PRI] = { 0 };
		const char *fifo_consumer_wrapup_sound = NULL;
		const char *fifo_consumer_wrapup_key = NULL;
		const char *sfifo_consumer_wrapup_time = NULL;
		uint32_t fifo_consumer_wrapup_time = 0;
		switch_time_t wrapup_time_elapsed = 0, wrapup_time_started = 0, wrapup_time_remaining = 0;
		const char *my_id;
		char buf[5] = "";
		const char *strat_str = switch_channel_get_variable(channel, "fifo_strategy");
		fifo_strategy_t strat = STRAT_WAITING_LONGER;
		const char *url = NULL;
		const char *caller_uuid = NULL;
		switch_event_t *call_event;
		const char *outbound_id = switch_channel_get_variable(channel, "fifo_outbound_uuid");
		const char *track_use_count = switch_channel_get_variable(channel, "fifo_track_use_count");
		int do_track = switch_true(track_use_count);

		if (!zstr(strat_str)) {
			if (!strcasecmp(strat_str, "more_ppl")) {
				strat = STRAT_MORE_PPL;
			} else if (!strcasecmp(strat_str, "waiting_longer")) {
				strat = STRAT_WAITING_LONGER;
			} else {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Invalid strategy\n");
				goto done;
			}
		}

		if (argc > 2) {
			if (!strcasecmp(argv[2], "nowait")) {
				do_wait = 0;
			} else if (strcasecmp(argv[2], "wait")) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "USAGE %s\n", FIFO_USAGE);
				goto done;
			}
		}

		if (!(my_id = switch_channel_get_variable(channel, "fifo_consumer_id"))) {
			my_id = switch_core_session_get_uuid(session);
		}

		if (do_wait) {
			for (i = 0; i < node_count; i++) {
				if (!(node = node_list[i])) {
					continue;
				}
				switch_mutex_lock(node->mutex);
				node->consumer_count++;
				switch_core_hash_insert(node->consumer_hash, switch_core_session_get_uuid(session), session);
				switch_mutex_unlock(node->mutex);
			}
			switch_channel_answer(channel);
		}

		if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
			switch_channel_event_set_data(channel, event);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", argv[0]);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "consumer_start");
			switch_event_fire(&event);
		}

		ts = switch_micro_time_now();
		switch_time_exp_lt(&tm, ts);
		switch_strftime_nocheck(date, &retsize, sizeof(date), "%Y-%m-%d %T", &tm);
		switch_channel_set_variable(channel, "fifo_status", "WAITING");
		switch_channel_set_variable(channel, "fifo_timestamp", date);

		if ((pop_order = switch_channel_get_variable(channel, "fifo_pop_order"))) {
			char *tmp = switch_core_session_strdup(session, pop_order);
			int x;
			custom_pop = switch_separate_string(tmp, ',', pop_list, (sizeof(pop_list) / sizeof(pop_list[0])));
			if (custom_pop >= MAX_PRI) {
				custom_pop = MAX_PRI - 1;
			}

			for (x = 0; x < custom_pop; x++) {
				int temp;
				switch_assert(pop_list[x]);
				temp = atoi(pop_list[x]);
				if (temp > -1 && temp < MAX_PRI) {
					pop_array[x] = temp;
				}
			}
		}

		while (switch_channel_ready(channel)) {
			int x = 0, winner = -1;
			switch_time_t longest = (0xFFFFFFFFFFFFFFFFULL / 2);
			uint32_t importance = 0, waiting = 0, most_waiting = 0;
			
			pop = NULL;

			if (moh && do_wait) {
				switch_status_t moh_status;
				memset(&args, 0, sizeof(args));
				args.read_frame_callback = consumer_read_frame_callback;
				args.user_data = node_list;
				moh_status = switch_ivr_play_file(session, NULL, moh, &args);

				if (!SWITCH_READ_ACCEPTABLE(moh_status)) {
					break;
				}
			}

			for (i = 0; i < node_count; i++) {
				if (!(node = node_list[i])) {
					continue;
				}

				if ((waiting = node_consumer_wait_count(node))) {

					if (!importance || node->importance > importance) {
						if (strat == STRAT_WAITING_LONGER) {
							if (node->start_waiting < longest) {
								longest = node->start_waiting;
								winner = i;
							}
						} else {
							if (waiting > most_waiting) {
								most_waiting = waiting;
								winner = i;
							}
						}
					}

					if (node->importance > importance) {
						importance = node->importance;
					}
				}
			}

			if (winner > -1) {
				node = node_list[winner];
			} else {
				node = NULL;
			}

			if (node) {
				const char *varval;

				if ((varval = switch_channel_get_variable(channel, "fifo_bridge_uuid"))) {
					for (x = 0; x < MAX_PRI; x++) {
						if (fifo_queue_pop_nameval(node->fifo_list[pop_array[x]], "unique-id", varval, &pop, SWITCH_TRUE) == SWITCH_STATUS_SUCCESS && pop) {
							break;
						}
					}
				}

				if (!pop && (varval = switch_channel_get_variable(channel, "fifo_target_skill"))) {
					for (x = 0; x < MAX_PRI; x++) {
						if (fifo_queue_pop_nameval(node->fifo_list[pop_array[x]], "variable_fifo_skill", 
												   varval, &pop, SWITCH_TRUE) == SWITCH_STATUS_SUCCESS && pop) {
							break;
						}
					}
				}

				if (!pop) {
					for (x = 0; x < MAX_PRI; x++) {
						if (fifo_queue_pop_nameval(node->fifo_list[pop_array[x]], "variable_fifo_vip", "true", 
												   &pop, SWITCH_TRUE) == SWITCH_STATUS_SUCCESS && pop) {
							break;
						}
					}
				}

				if (!pop) {
					if (custom_pop) {
						for (x = 0; x < MAX_PRI; x++) {
							if (fifo_queue_pop(node->fifo_list[pop_array[x]], &pop, SWITCH_TRUE) == SWITCH_STATUS_SUCCESS && pop) {
								break;
							}
						}
					} else {
						for (x = 0; x < MAX_PRI; x++) {
							if (fifo_queue_pop(node->fifo_list[x], &pop, SWITCH_TRUE) == SWITCH_STATUS_SUCCESS && pop) {
								break;
							}
						}
					}
				}

				if (pop && !node_consumer_wait_count(node)) {
					switch_mutex_lock(node->mutex);
					node->start_waiting = 0;
					switch_mutex_unlock(node->mutex);
				}
			}

			if (!pop) {
				if (!do_wait) {
					break;
				}

				status = switch_core_session_read_frame(session, &read_frame, SWITCH_IO_FLAG_NONE, 0);

				if (!SWITCH_READ_ACCEPTABLE(status)) {
					break;
				}

				continue;
			}

			call_event = (switch_event_t *) pop;
			pop = NULL;
			
			url = switch_event_get_header(call_event, "dial-url");
			caller_uuid = switch_event_get_header(call_event, "unique-id");

			if (url) {
				switch_call_cause_t cause = SWITCH_CAUSE_NONE;
				const char *o_announce = NULL;
				
				if ((o_announce = switch_channel_get_variable(channel, "fifo_outbound_announce"))) {
					switch_ivr_play_file(session, NULL, o_announce, NULL);
				}

				if (switch_ivr_originate(session, &other_session, &cause, url, 120, NULL, NULL, NULL, NULL, NULL, SOF_NONE, NULL) != SWITCH_STATUS_SUCCESS) {
					other_session = NULL;
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Originate to [%s] failed, cause: %s\n", url,
									  switch_channel_cause2str(cause));

					if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
						switch_channel_event_set_data(channel, event);
						switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", argv[0]);
						switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "caller_outbound");
						switch_event_add_header(event, SWITCH_STACK_BOTTOM, "FIFO-Result", "failure:%s", switch_channel_cause2str(cause));
						switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Outbound-URL", url);
						switch_event_fire(&event);
					}

				} else {
					if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
						switch_channel_event_set_data(channel, event);
						switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", argv[0]);
						switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "caller_outbound");
						switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Result", "success");
						switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Outbound-URL", url);
						switch_event_fire(&event);
					}
					url = NULL;
					caller_uuid = switch_core_session_strdup(session, switch_core_session_get_uuid(other_session));
				}

			} else {
				if ((other_session = switch_core_session_locate(caller_uuid))) {
					switch_channel_t *other_channel = switch_core_session_get_channel(other_session);
					if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
						switch_channel_event_set_data(other_channel, event);
						switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", argv[0]);
						switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "caller_pop");
						switch_event_fire(&event);
					}
				}
			}

			if (node && other_session) {
				switch_channel_t *other_channel = switch_core_session_get_channel(other_session);
				switch_caller_profile_t *cloned_profile;
				const char *o_announce = NULL;
				const char *record_template = switch_channel_get_variable(channel, "fifo_record_template");
				char *expanded = NULL;
				char *sql = NULL;
				long epoch_start, epoch_end;

				if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
					switch_channel_event_set_data(channel, event);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", argv[0]);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "consumer_pop");
					switch_event_fire(&event);
				}

				if ((o_announce = switch_channel_get_variable(other_channel, "fifo_override_announce"))) {
					announce = o_announce;
				}

				if (announce) {
					switch_ivr_play_file(session, NULL, announce, NULL);
				} else {
					switch_ivr_sleep(session, 500, SWITCH_TRUE, NULL);
				}

				switch_channel_set_variable(other_channel, "fifo_serviced_by", my_id);
				switch_channel_set_variable(other_channel, "fifo_serviced_uuid", switch_core_session_get_uuid(session));

				switch_channel_set_flag(other_channel, CF_BREAK);

				while (switch_channel_ready(channel) && switch_channel_ready(other_channel) && switch_channel_test_app_flag(other_channel, CF_APP_TAGGED)) {
					status = switch_core_session_read_frame(session, &read_frame, SWITCH_IO_FLAG_NONE, 0);
					if (!SWITCH_READ_ACCEPTABLE(status)) {
						break;
					}
				}

				if (!(switch_channel_ready(channel))) {
					const char *app = switch_channel_get_variable(other_channel, "current_application");
					const char *arg = switch_channel_get_variable(other_channel, "current_application_data");
					switch_caller_extension_t *extension = NULL;

					switch_mutex_lock(node->mutex);
					node->caller_count--;
					switch_mutex_unlock(node->mutex);
					send_presence(node);
					check_cancel(node);


					if (app) {
						extension = switch_caller_extension_new(other_session, app, arg);
						switch_caller_extension_add_application(other_session, extension, app, arg);
						switch_channel_set_caller_extension(other_channel, extension);
						switch_channel_set_state(other_channel, CS_EXECUTE);
					} else {
						switch_channel_hangup(other_channel, SWITCH_CAUSE_NORMAL_CLEARING);
					}

					switch_core_session_rwunlock(other_session);
					break;
				}
				
				switch_channel_answer(channel);
				cloned_profile = switch_caller_profile_clone(other_session, switch_channel_get_caller_profile(channel));
				switch_assert(cloned_profile);
				switch_channel_set_originator_caller_profile(other_channel, cloned_profile);

				cloned_profile = switch_caller_profile_clone(session, switch_channel_get_caller_profile(other_channel));
				switch_assert(cloned_profile);
				switch_assert(cloned_profile->next == NULL);
				switch_channel_set_originatee_caller_profile(channel, cloned_profile);

				ts = switch_micro_time_now();
				switch_time_exp_lt(&tm, ts);
				epoch_start = (long)switch_epoch_time_now(NULL);
				switch_strftime_nocheck(date, &retsize, sizeof(date), "%Y-%m-%d %T", &tm);
				switch_channel_set_variable(channel, "fifo_status", "TALKING");
				switch_channel_set_variable(channel, "fifo_target", caller_uuid);
				switch_channel_set_variable(channel, "fifo_timestamp", date);
				switch_channel_set_variable_printf(channel, "fifo_epoch_start_bridge", "%ld", epoch_start);
				switch_channel_set_variable(channel, "fifo_role", "consumer");

				switch_channel_set_variable(other_channel, "fifo_status", "TALKING");
				switch_channel_set_variable(other_channel, "fifo_timestamp", date);
				switch_channel_set_variable_printf(other_channel, "fifo_epoch_start_bridge", "%ld", epoch_start);
				switch_channel_set_variable(other_channel, "fifo_target", switch_core_session_get_uuid(session));
				switch_channel_set_variable(other_channel, "fifo_role", "caller");

				send_presence(node);

				if (record_template) {
					expanded = switch_channel_expand_variables(other_channel, record_template);
					switch_ivr_record_session(session, expanded, 0, NULL);
				}

				switch_core_media_bug_resume(session);
				switch_core_media_bug_resume(other_session);
				switch_process_import(session, other_channel, "fifo_caller_consumer_import");
				switch_process_import(other_session, channel, "fifo_consumer_caller_import");
				if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
					switch_channel_event_set_data(channel, event);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", argv[0]);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "bridge-consumer-start");
					switch_event_fire(&event);
				}
				if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
					switch_channel_event_set_data(other_channel, event);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", argv[0]);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "bridge-caller-start");
					switch_event_fire(&event);
				}

				if (outbound_id && do_track) {
					sql = switch_mprintf("update fifo_outbound set use_count=use_count+1,outbound_fail_count=0 where uuid='%s'", outbound_id);

					fifo_execute_sql(sql, globals.sql_mutex);
					switch_safe_free(sql);
				}

				sql = switch_mprintf("insert into fifo_bridge "
									 "(fifo_name,caller_uuid,caller_caller_id_name,caller_caller_id_number,consumer_uuid,consumer_outgoing_uuid,bridge_start) "
									 "values ('%q','%q','%q','%q','%q','%q',%ld)",
									 node->name,
									 switch_core_session_get_uuid(other_session),
									 switch_str_nil(switch_channel_get_variable(other_channel, "caller_id_name")),
									 switch_str_nil(switch_channel_get_variable(other_channel, "caller_id_number")),
									 switch_core_session_get_uuid(session),
									 switch_str_nil(outbound_id),
									 (long) switch_epoch_time_now(NULL)
									 );
					
			
				fifo_execute_sql(sql, globals.sql_mutex);
				switch_safe_free(sql);

				switch_ivr_multi_threaded_bridge(session, other_session, on_dtmf, other_session, session);


				if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
					switch_channel_event_set_data(channel, event);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", argv[0]);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "bridge-consumer-stop");
					switch_event_fire(&event);
				}
				if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
					switch_channel_event_set_data(other_channel, event);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", argv[0]);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "bridge-caller-stop");
					switch_event_fire(&event);
				}
				
				if (outbound_id && do_track) {
					sql = switch_mprintf("update fifo_outbound set use_count=use_count-1, outbound_call_total_count=outbound_call_total_count+1 "
										 "outbound_call_count=outbound_call_count+1, next_avail=%ld + lag where uuid='%s' and use_count > 0", 
										 (long) switch_epoch_time_now(NULL), outbound_id);

					fifo_execute_sql(sql, globals.sql_mutex);
					switch_safe_free(sql);
				}

				epoch_end = (long)switch_epoch_time_now(NULL);

				switch_channel_set_variable_printf(channel, "fifo_epoch_stop_bridge", "%ld", epoch_end);
				switch_channel_set_variable_printf(channel, "fifo_bridge_seconds", "%d", epoch_end - epoch_start);

				switch_channel_set_variable_printf(other_channel, "fifo_epoch_stop_bridge", "%ld", epoch_end);
				switch_channel_set_variable_printf(other_channel, "fifo_bridge_seconds", "%d", epoch_end - epoch_start);

				sql = switch_mprintf("delete from fifo_bridge where consumer_uuid='%q'", switch_core_session_get_uuid(session));
				fifo_execute_sql(sql, globals.sql_mutex);
				switch_safe_free(sql);

				
				switch_core_media_bug_pause(session);
				switch_core_media_bug_pause(other_session);

				if (record_template) {
					switch_ivr_stop_record_session(session, expanded);
					if (expanded != record_template) {
						switch_safe_free(expanded);
					}
				}

				ts = switch_micro_time_now();
				switch_time_exp_lt(&tm, ts);
				switch_strftime_nocheck(date, &retsize, sizeof(date), "%Y-%m-%d %T", &tm);
				switch_channel_set_variable(channel, "fifo_status", "WAITING");
				switch_channel_set_variable(channel, "fifo_timestamp", date);

				switch_channel_set_variable(other_channel, "fifo_status", "DONE");
				switch_channel_set_variable(other_channel, "fifo_timestamp", date);

				switch_mutex_lock(node->mutex);
				node->caller_count--;
				switch_mutex_unlock(node->mutex);
				send_presence(node);
				check_cancel(node);
				switch_core_session_rwunlock(other_session);
				if (call_event) {
					switch_event_destroy(&call_event);
				}

				if (!do_wait || !switch_channel_ready(channel)) {
					break;
				}

				fifo_consumer_wrapup_sound = switch_channel_get_variable(channel, "fifo_consumer_wrapup_sound");
				fifo_consumer_wrapup_key = switch_channel_get_variable(channel, "fifo_consumer_wrapup_key");
				sfifo_consumer_wrapup_time = switch_channel_get_variable(channel, "fifo_consumer_wrapup_time");
				if (!zstr(sfifo_consumer_wrapup_time)) {
					fifo_consumer_wrapup_time = atoi(sfifo_consumer_wrapup_time);
				} else {
					fifo_consumer_wrapup_time = 5000;
				}

				memset(buf, 0, sizeof(buf));

				if (fifo_consumer_wrapup_time || !zstr(fifo_consumer_wrapup_key)) {
					switch_channel_set_variable(channel, "fifo_status", "WRAPUP");
					if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
						switch_channel_event_set_data(channel, event);
						switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", argv[0]);
						switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "consumer_wrapup");
						switch_event_fire(&event);
					}
				}

				if (!zstr(fifo_consumer_wrapup_sound)) {
					memset(&args, 0, sizeof(args));
					args.buf = buf;
					args.buflen = sizeof(buf);
					switch_ivr_play_file(session, NULL, fifo_consumer_wrapup_sound, &args);
				}

				if (fifo_consumer_wrapup_time) {
					wrapup_time_started = switch_micro_time_now();
				}

				if (!zstr(fifo_consumer_wrapup_key) && strcmp(buf, fifo_consumer_wrapup_key)) {
					while (switch_channel_ready(channel)) {
						char terminator = 0;

						if (fifo_consumer_wrapup_time) {
							wrapup_time_elapsed = (switch_micro_time_now() - wrapup_time_started) / 1000;
							if (wrapup_time_elapsed > fifo_consumer_wrapup_time) {
								break;
							} else {
								wrapup_time_remaining = fifo_consumer_wrapup_time - wrapup_time_elapsed + 100;
							}
						}

						switch_ivr_collect_digits_count(session, buf, sizeof(buf) - 1, 1, fifo_consumer_wrapup_key, &terminator, 0, 0,
														(uint32_t) wrapup_time_remaining);
						if ((terminator == *fifo_consumer_wrapup_key) || !(switch_channel_ready(channel))) {
							break;
						}

					}
				} else if (fifo_consumer_wrapup_time && (zstr(fifo_consumer_wrapup_key) || !strcmp(buf, fifo_consumer_wrapup_key))) {
					while (switch_channel_ready(channel)) {
						wrapup_time_elapsed = (switch_micro_time_now() - wrapup_time_started) / 1000;
						if (wrapup_time_elapsed > fifo_consumer_wrapup_time) {
							break;
						}
						switch_yield(500);
					}
				}
				switch_channel_set_variable(channel, "fifo_status", "WAITING");
			}

			if (do_wait && switch_channel_ready(channel)) {
				if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
					switch_channel_event_set_data(channel, event);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", argv[0]);
					switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "consumer_reentrance");
					switch_event_fire(&event);
				}
			}
		}

		if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, FIFO_EVENT) == SWITCH_STATUS_SUCCESS) {
			switch_channel_event_set_data(channel, event);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Name", argv[0]);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "FIFO-Action", "consumer_stop");
			switch_event_fire(&event);
		}

		if (do_wait) {
			for (i = 0; i < node_count; i++) {
				if (!(node = node_list[i])) {
					continue;
				}
				switch_mutex_lock(node->mutex);
				switch_core_hash_delete(node->consumer_hash, switch_core_session_get_uuid(session));
				node->consumer_count--;
				switch_mutex_unlock(node->mutex);
			}
		}
	}

  done:

	switch_mutex_lock(globals.mutex);
	if (node && node->ready == FIFO_DELAY_DESTROY && node->consumer_count == 0 && node->caller_count == 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE, "%s removed.\n", node->name);
		switch_core_hash_delete(globals.fifo_hash, node->name);
		switch_thread_rwlock_wrlock(node->rwlock);
		node->ready = 0;
		switch_mutex_lock(node->mutex);
		switch_core_hash_destroy(&node->consumer_hash);
		switch_mutex_unlock(node->mutex);
		switch_thread_rwlock_unlock(node->rwlock);
		switch_core_destroy_memory_pool(&node->pool);

	}
	switch_mutex_unlock(globals.mutex);


	switch_channel_clear_app_flag(channel, CF_APP_TAGGED);

	switch_core_media_bug_resume(session);

}

struct xml_helper {
	switch_xml_t xml;
	fifo_node_t *node;
	char *container;
	char *tag;
	int cc_off;
	int row_off;
	int verbose;
};

static int xml_callback(void *pArg, int argc, char **argv, char **columnNames)
{
	struct xml_helper *h = (struct xml_helper *) pArg;
	switch_xml_t x_out;
	int c_off = 0;
	char exp_buf[128] = "";
	switch_time_exp_t tm;
	switch_time_t etime = 0;
	char atime[128] = "";
	char *expires = exp_buf, *tb = atime;
	int arg = 0;

	for(arg = 0; arg < argc; arg++) {
		if (!argv[arg]) {
			argv[arg] = "";
		}
	}

	arg = 0;

	if (argv[7]) {
		if ((etime = atol(argv[7]))) {
			switch_size_t retsize;

			switch_time_exp_lt(&tm, switch_time_from_sec(etime));
			switch_strftime_nocheck(exp_buf, &retsize, sizeof(exp_buf), "%Y-%m-%d %T", &tm);
		} else {
			switch_set_string(exp_buf, "now");
		}
	}


	if (atoi(argv[13])) {
		arg = 17;
	} else {
		arg = 18;
	}


	if ((etime = atol(argv[arg]))) {
		switch_size_t retsize;
		
		switch_time_exp_lt(&tm, switch_time_from_sec(etime));
		switch_strftime_nocheck(atime, &retsize, sizeof(atime), "%Y-%m-%d %T", &tm);
	} else {
		switch_set_string(atime, "now");
	}


	x_out = switch_xml_add_child_d(h->xml, h->tag, c_off++);
	switch_xml_set_attr_d(x_out, "simo", argv[3]);
	switch_xml_set_attr_d(x_out, "use_count", argv[4]);
	switch_xml_set_attr_d(x_out, "timeout", argv[5]);
	switch_xml_set_attr_d(x_out, "lag", argv[6]);
	switch_xml_set_attr_d(x_out, "outbound-call-count", argv[10]);
	switch_xml_set_attr_d(x_out, "outbound-fail-count", argv[11]);
	switch_xml_set_attr_d(x_out, "taking-calls", argv[13]);
	switch_xml_set_attr_d(x_out, "status", argv[14]);

	switch_xml_set_attr_d(x_out, "outbound_call_total_count", argv[15]);
	switch_xml_set_attr_d(x_out, "outbound_fail_total_count", argv[16]);
	
	if (arg == 17) {
		switch_xml_set_attr_d(x_out, "logged_on_since", tb);
	} else {
		switch_xml_set_attr_d(x_out, "logged_off_since", tb);
	}

	switch_xml_set_attr_d(x_out, "manual_calls_out_count", argv[19]);
	switch_xml_set_attr_d(x_out, "manual_calls_in_count", argv[20]);
	switch_xml_set_attr_d(x_out, "manual_calls_out_total_count", argv[21]);
	switch_xml_set_attr_d(x_out, "manual_calls_in_total_count", argv[22]);
	

	switch_xml_set_attr_d(x_out, "next-available", expires);

	switch_xml_set_txt_d(x_out, argv[2]);

	return 0;
}

static int xml_outbound(switch_xml_t xml, fifo_node_t *node, char *container, char *tag, int cc_off, int verbose)
{
	struct xml_helper h = { 0 };
	char *sql;

	if (!strcmp(node->name, MANUAL_QUEUE_NAME)) {

		sql = switch_mprintf("select uuid, '%s', originate_string, simo_count, use_count, timeout,"
							 "lag, next_avail, expires, static, outbound_call_count, outbound_fail_count,"
							 "hostname, taking_calls, status, outbound_call_total_count, outbound_fail_total_count, active_time, inactive_time,"
							 "manual_calls_out_count, manual_calls_in_count, manual_calls_out_total_count, manual_calls_in_total_count from fifo_outbound "
							 "group by "
							 "uuid, originate_string, simo_count, use_count, timeout,"
							 "lag, next_avail, expires, static, outbound_call_count, outbound_fail_count,"
							 "hostname, taking_calls, status, outbound_call_total_count, outbound_fail_total_count, active_time, inactive_time,"
							 "manual_calls_out_count, manual_calls_in_count, manual_calls_out_total_count, manual_calls_in_total_count",
							 MANUAL_QUEUE_NAME);


	} else {
		sql = switch_mprintf("select uuid, fifo_name, originate_string, simo_count, use_count, timeout, "
							 "lag, next_avail, expires, static, outbound_call_count, outbound_fail_count, "
							 "hostname, taking_calls, status, outbound_call_total_count, outbound_fail_total_count, active_time, inactive_time, "
							 "manual_calls_out_count, manual_calls_in_count, manual_calls_out_total_count, manual_calls_in_total_count "
							 "from fifo_outbound where fifo_name = '%q'", node->name);
	}

	h.xml = xml;
	h.node = node;
	h.container = container;
	h.tag = tag;
	h.cc_off = cc_off;
	h.row_off = 0;
	h.verbose = verbose;

	h.xml = switch_xml_add_child_d(h.xml, h.container, h.cc_off++);

	fifo_execute_sql_callback(globals.sql_mutex, sql, xml_callback, &h);

	switch_safe_free(sql);

	return h.cc_off;
}


static int xml_bridge_callback(void *pArg, int argc, char **argv, char **columnNames)
{
	struct xml_helper *h = (struct xml_helper *) pArg;
	switch_xml_t x_bridge, x_var, x_caller, x_consumer, x_cdr;
	char exp_buf[128] = "";
	switch_time_exp_t tm;
	switch_time_t etime = 0;
	int off = 0, tag_off = 0;
	switch_core_session_t *session;
	char url_buf[512] = "";
	char *encoded;

	if ((etime = atol(argv[6]))) {
		switch_size_t retsize;
		
		switch_time_exp_lt(&tm, switch_time_from_sec(etime));
		switch_strftime_nocheck(exp_buf, &retsize, sizeof(exp_buf), "%Y-%m-%d %T", &tm);
	} else {
		switch_set_string(exp_buf, "now");
	}


	x_bridge = switch_xml_add_child_d(h->xml, h->tag, h->row_off++);

	switch_xml_set_attr_d(x_bridge, "fifo_name", argv[0]);
	switch_xml_set_attr_d_buf(x_bridge, "bridge_start", exp_buf);
	switch_xml_set_attr_d(x_bridge, "bridge_start_epoch", argv[6]);

	x_caller = switch_xml_add_child_d(x_bridge, "caller", tag_off++);
	
	switch_xml_set_attr_d(x_caller, "uuid", argv[1]);
	
	encoded = switch_url_encode(argv[2], url_buf, sizeof(url_buf));
	switch_xml_set_attr_d(x_caller, "caller_id_name", encoded);

	encoded = switch_url_encode(argv[3], url_buf, sizeof(url_buf));
	switch_xml_set_attr_d(x_caller, "caller_id_number", encoded);



	if (h->verbose) {
		if ((session = switch_core_session_locate(argv[1]))) {
			x_cdr = switch_xml_add_child_d(x_caller, "cdr", 0);
			switch_ivr_generate_xml_cdr(session, &x_cdr);
			switch_core_session_rwunlock(session);
		}
	} 

	off = 0;

	x_consumer = switch_xml_add_child_d(x_bridge, "consumer", tag_off++);

	x_var = switch_xml_add_child_d(x_consumer, "uuid", off++);
	switch_xml_set_txt_d(x_var, argv[4]);
	x_var = switch_xml_add_child_d(x_consumer, "outgoing_uuid", off++);
	switch_xml_set_txt_d(x_var, argv[5]);

	if (h->verbose) {
		if ((session = switch_core_session_locate(argv[1]))) {
			x_cdr = switch_xml_add_child_d(x_consumer, "cdr", 0);
			switch_ivr_generate_xml_cdr(session, &x_cdr);
			switch_core_session_rwunlock(session);
		}
	}

	return 0;
}

static int xml_bridges(switch_xml_t xml, fifo_node_t *node, char *container, char *tag, int cc_off, int verbose)
{
	struct xml_helper h = { 0 };
	char *sql = switch_mprintf("select "
							   "fifo_name,caller_uuid,caller_caller_id_name,caller_caller_id_number,consumer_uuid,consumer_outgoing_uuid,bridge_start "
							   "from fifo_bridge where fifo_name = '%q'", node->name);

	h.xml = xml;
	h.node = node;
	h.container = container;
	h.tag = tag;
	h.cc_off = cc_off;
	h.row_off = 0;
	h.verbose = verbose;

	h.xml = switch_xml_add_child_d(h.xml, h.container, h.cc_off++);

	fifo_execute_sql_callback(globals.sql_mutex, sql, xml_bridge_callback, &h);

	switch_safe_free(sql);

	return h.cc_off;
}

static int xml_hash(switch_xml_t xml, switch_hash_t *hash, char *container, char *tag, int cc_off, int verbose)
{
	switch_xml_t x_tmp, x_caller, x_cp;
	switch_hash_index_t *hi;
	switch_core_session_t *session;
	switch_channel_t *channel;
	void *val;
	const void *var;
	
	x_tmp = switch_xml_add_child_d(xml, container, cc_off++);
	switch_assert(x_tmp);

	for (hi = switch_hash_first(NULL, hash); hi; hi = switch_hash_next(hi)) {
		int c_off = 0, d_off = 0;
		const char *status;
		const char *ts;
		char url_buf[512] = "";
		char *encoded;

		switch_hash_this(hi, &var, NULL, &val);
		session = (switch_core_session_t *) val;
		channel = switch_core_session_get_channel(session);
		x_caller = switch_xml_add_child_d(x_tmp, tag, c_off++);
		switch_assert(x_caller);

		switch_xml_set_attr_d(x_caller, "uuid", switch_core_session_get_uuid(session));

		if ((status = switch_channel_get_variable(channel, "fifo_status"))) {
			switch_xml_set_attr_d(x_caller, "status", status);
		}
		
		if ((status = switch_channel_get_variable(channel, "caller_id_name"))) {
			encoded = switch_url_encode(status, url_buf, sizeof(url_buf));
			switch_xml_set_attr_d(x_caller, "caller_id_name", encoded);
		}

		if ((status = switch_channel_get_variable(channel, "caller_id_number"))) {
			encoded = switch_url_encode(status, url_buf, sizeof(url_buf));
			switch_xml_set_attr_d(x_caller, "caller_id_number", encoded);
		}

		if ((ts = switch_channel_get_variable(channel, "fifo_timestamp"))) {
			switch_xml_set_attr_d(x_caller, "timestamp", ts);
		}

		if ((ts = switch_channel_get_variable(channel, "fifo_target"))) {
			switch_xml_set_attr_d(x_caller, "target", ts);
		}

		if (verbose) {
			if (!(x_cp = switch_xml_add_child_d(x_caller, "cdr", d_off++))) {
				abort();
			}

			switch_ivr_generate_xml_cdr(session, &x_cp);
		}
	}

	return cc_off;
}


static int xml_caller(switch_xml_t xml, fifo_node_t *node, char *container, char *tag, int cc_off, int verbose)
{
	switch_xml_t x_tmp, x_caller, x_cp;
	int i, x;
	switch_core_session_t *session;
	switch_channel_t *channel;

	x_tmp = switch_xml_add_child_d(xml, container, cc_off++);
	switch_assert(x_tmp);

	for (x = 0; x < MAX_PRI; x++) {
		fifo_queue_t *q = node->fifo_list[x];

		switch_mutex_lock(q->mutex);

		for (i = 0; i < q->idx; i++) {
			
			int c_off = 0, d_off = 0;
			const char *status;
			const char *ts;
			const char *uuid = switch_event_get_header(q->data[i], "unique-id");
			char sl[30] = "";
			char url_buf[512] = "";
			char *encoded;
			
			if (!uuid) {
				continue;
			}

			if (!(session = switch_core_session_locate(uuid))) {
				continue;
			}

			channel = switch_core_session_get_channel(session);
			x_caller = switch_xml_add_child_d(x_tmp, tag, c_off++);
			switch_assert(x_caller);

			switch_xml_set_attr_d(x_caller, "uuid", switch_core_session_get_uuid(session));

			if ((status = switch_channel_get_variable(channel, "fifo_status"))) {
				switch_xml_set_attr_d(x_caller, "status", status);
			}

			if ((status = switch_channel_get_variable(channel, "caller_id_name"))) {
				encoded = switch_url_encode(status, url_buf, sizeof(url_buf));
				switch_xml_set_attr_d(x_caller, "caller_id_name", encoded);
			}
			
			if ((status = switch_channel_get_variable(channel, "caller_id_number"))) {
				encoded = switch_url_encode(status, url_buf, sizeof(url_buf));
				switch_xml_set_attr_d(x_caller, "caller_id_number", encoded);
			}

			if ((ts = switch_channel_get_variable(channel, "fifo_timestamp"))) {
				switch_xml_set_attr_d(x_caller, "timestamp", ts);
			}

			if ((ts = switch_channel_get_variable(channel, "fifo_target"))) {
				switch_xml_set_attr_d(x_caller, "target", ts);
			}

			if ((ts = switch_channel_get_variable(channel, "fifo_position"))) {
				switch_xml_set_attr_d(x_caller, "position", ts);
			}

			switch_snprintf(sl, sizeof(sl), "%d", x);
			switch_xml_set_attr_d_buf(x_caller, "slot", sl);


			if (verbose) {
				if (!(x_cp = switch_xml_add_child_d(x_caller, "cdr", d_off++))) {
					abort();
				}
				
				switch_ivr_generate_xml_cdr(session, &x_cp);
			}

			switch_core_session_rwunlock(session);
			session = NULL;
		}

		switch_mutex_unlock(q->mutex);
	}

	return cc_off;
}

static void list_node(fifo_node_t *node, switch_xml_t x_report, int *off, int verbose)
{
	switch_xml_t x_fifo;
	int cc_off = 0;
	char buffer[35];
	char *tmp = buffer;

	x_fifo = switch_xml_add_child_d(x_report, "fifo", (*off)++);;
	switch_assert(x_fifo);

	switch_xml_set_attr_d(x_fifo, "name", node->name);
	switch_snprintf(tmp, sizeof(buffer), "%d", node->consumer_count);
	switch_xml_set_attr_d(x_fifo, "consumer_count", tmp);
	switch_snprintf(tmp, sizeof(buffer), "%d", node->caller_count);
	switch_xml_set_attr_d(x_fifo, "caller_count", tmp);
	switch_snprintf(tmp, sizeof(buffer), "%d", node_consumer_wait_count(node));
	switch_xml_set_attr_d(x_fifo, "waiting_count", tmp);
	switch_snprintf(tmp, sizeof(buffer), "%u", node->importance);
	switch_xml_set_attr_d(x_fifo, "importance", tmp);

	switch_snprintf(tmp, sizeof(buffer), "%u", node->outbound_per_cycle);
	switch_xml_set_attr_d(x_fifo, "outbound_per_cycle", tmp);

	switch_xml_set_attr_d(x_fifo, "outbound_strategy", strat_parse(node->outbound_strategy));

	cc_off = xml_outbound(x_fifo, node, "outbound", "member", cc_off, verbose);
	cc_off = xml_caller(x_fifo, node, "callers", "caller", cc_off, verbose);
	cc_off = xml_hash(x_fifo, node->consumer_hash, "consumers", "consumer", cc_off, verbose);
	cc_off = xml_bridges(x_fifo, node, "bridges", "bridge", cc_off, verbose);
}



#define FIFO_API_SYNTAX "list|list_verbose|count|importance [<fifo name>]|reparse [del_all]"
SWITCH_STANDARD_API(fifo_api_function)
{
	int len = 0;
	fifo_node_t *node;
	char *data = NULL;
	int argc = 0;
	char *argv[5] = { 0 };
	switch_hash_index_t *hi;
	void *val;
	const void *var;
	int x = 0, verbose = 0;

	if (!globals.running) {
		return SWITCH_STATUS_FALSE;
	}

	if (!zstr(cmd)) {
		data = strdup(cmd);
		switch_assert(data);
	}

	if (zstr(cmd) || (argc = switch_separate_string(data, ' ', argv, (sizeof(argv) / sizeof(argv[0])))) < 1 || !argv[0]) {
		stream->write_function(stream, "%s\n", FIFO_API_SYNTAX);
		return SWITCH_STATUS_SUCCESS;
	}

	switch_mutex_lock(globals.mutex);
	verbose = !strcasecmp(argv[0], "list_verbose");

	if (!strcasecmp(argv[0], "reparse")) {
		load_config(1, argv[1] && !strcasecmp(argv[1], "del_all"));
		goto done;
	}

	if (!strcasecmp(argv[0], "list") || verbose) {
		char *xml_text = NULL;
		switch_xml_t x_report = switch_xml_new("fifo_report");
		switch_assert(x_report);

		if (argc < 2) {
			for (hi = switch_hash_first(NULL, globals.fifo_hash); hi; hi = switch_hash_next(hi)) {
				switch_hash_this(hi, &var, NULL, &val);
				node = (fifo_node_t *) val;
				switch_mutex_lock(node->mutex);
				list_node(node, x_report, &x, verbose);
				switch_mutex_unlock(node->mutex);
			}
		} else {
			if ((node = switch_core_hash_find(globals.fifo_hash, argv[1]))) {
				switch_mutex_lock(node->mutex);
				list_node(node, x_report, &x, verbose);
				switch_mutex_unlock(node->mutex);
			}
		}
		xml_text = switch_xml_toxml(x_report, SWITCH_FALSE);
		switch_assert(xml_text);
		stream->write_function(stream, "%s\n", xml_text);
		switch_xml_free(x_report);
		switch_safe_free(xml_text);

	} else if (!strcasecmp(argv[0], "importance")) {
		if (argv[1] && (node = switch_core_hash_find(globals.fifo_hash, argv[1]))) {
			int importance = 0;
			if (argc > 2) {
				importance = atoi(argv[2]);
				if (importance < 0) {
					importance = 0;
				}
				node->importance = importance;
			}
			stream->write_function(stream, "importance: %u\n", node->importance);
		} else {
			stream->write_function(stream, "no fifo by that name\n");
		}
	} else if (!strcasecmp(argv[0], "count")) {
		if (argc < 2) {
			for (hi = switch_hash_first(NULL, globals.fifo_hash); hi; hi = switch_hash_next(hi)) {
				switch_hash_this(hi, &var, NULL, &val);
				node = (fifo_node_t *) val;
				len = node_consumer_wait_count(node);
				switch_mutex_lock(node->mutex);
				stream->write_function(stream, "%s:%d:%d:%d\n", (char *) var, node->consumer_count, node->caller_count, len);
				switch_mutex_unlock(node->mutex);
				x++;
			}

			if (!x) {
				stream->write_function(stream, "none\n");
			}
		} else if ((node = switch_core_hash_find(globals.fifo_hash, argv[1]))) {
			len = node_consumer_wait_count(node);
			switch_mutex_lock(node->mutex);
			stream->write_function(stream, "%s:%d:%d:%d\n", argv[1], node->consumer_count, node->caller_count, len);
			switch_mutex_unlock(node->mutex);
		} else {
			stream->write_function(stream, "none\n");
		}
	} else if (!strcasecmp(argv[0], "has_outbound")) {
		if (argc < 2) {
			for (hi = switch_hash_first(NULL, globals.fifo_hash); hi; hi = switch_hash_next(hi)) {
				switch_hash_this(hi, &var, NULL, &val);
				node = (fifo_node_t *) val;
				len = node_consumer_wait_count(node);
				switch_mutex_lock(node->mutex);
				stream->write_function(stream, "%s:%d\n", (char *) var, node->has_outbound);
				switch_mutex_unlock(node->mutex);
				x++;
			}

			if (!x) {
				stream->write_function(stream, "none\n");
			}
		} else if ((node = switch_core_hash_find(globals.fifo_hash, argv[1]))) {
			len = node_consumer_wait_count(node);
			switch_mutex_lock(node->mutex);
			stream->write_function(stream, "%s:%d\n", argv[1], node->has_outbound);
			switch_mutex_unlock(node->mutex);
		} else {
			stream->write_function(stream, "none\n");
		}
	} else {
		stream->write_function(stream, "-ERR Usage: %s\n", FIFO_API_SYNTAX);
	}

  done:

	switch_mutex_unlock(globals.mutex);
	return SWITCH_STATUS_SUCCESS;
}


const char outbound_sql[] =
	"create table fifo_outbound (\n"
	" uuid varchar(255),\n"
	" fifo_name varchar(255),\n"
	" originate_string varchar(255),\n"
	" simo_count integer,\n"
	" use_count integer,\n"
	" timeout integer,\n"
	" lag integer,\n"
	" next_avail integer not null default 0,\n"
	" expires integer not null default 0,\n"
	" static integer not null default 0,\n"
	" outbound_call_count integer not null default 0,\n"
	" outbound_fail_count integer not null default 0,\n"
	" hostname varchar(255),\n"
	" taking_calls integer not null default 1,\n"
	" status varchar(255),\n"
	" outbound_call_total_count integer not null default 0,\n"
	" outbound_fail_total_count integer not null default 0,\n"
	" active_time integer not null default 0,\n"
	" inactive_time integer not null default 0,\n"
	" manual_calls_out_count integer not null default 0,\n"
	" manual_calls_in_count integer not null default 0,\n"
	" manual_calls_out_total_count integer not null default 0,\n"
	" manual_calls_in_total_count integer not null default 0\n"
	");\n";


const char bridge_sql[] =
	"create table fifo_bridge (\n"
	" fifo_name varchar(1024) not null,\n"
	" caller_uuid varchar(255) not null,\n"
	" caller_caller_id_name varchar(255),\n"
	" caller_caller_id_number varchar(255),\n"

	" consumer_uuid varchar(255) not null,\n"
	" consumer_outgoing_uuid varchar(255),\n"
	" bridge_start integer\n"
	");\n"
;



static void extract_fifo_outbound_uuid(char *string, char *uuid, switch_size_t len)
{
	switch_event_t *ovars;
	char *parsed = NULL;
	const char *fifo_outbound_uuid;
	
	switch_event_create(&ovars, SWITCH_EVENT_REQUEST_PARAMS);
	
	switch_event_create_brackets(string, '{', '}', ',', &ovars, &parsed);
	
	if ((fifo_outbound_uuid = switch_event_get_header(ovars, "fifo_outbound_uuid"))) {
		switch_snprintf(uuid, len, "%s", fifo_outbound_uuid);
	}

	switch_safe_free(parsed);
	switch_event_destroy(&ovars);
}

static switch_status_t load_config(int reload, int del_all)
{
	char *cf = "fifo.conf";
	switch_xml_t cfg, xml, fifo, fifos, member, settings, param;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	char *sql;
	switch_bool_t delete_all_outbound_member_on_startup = SWITCH_FALSE;
	switch_cache_db_handle_t *dbh = NULL;
	fifo_node_t *node;

	gethostname(globals.hostname, sizeof(globals.hostname));

	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", cf);
		return SWITCH_STATUS_TERM;
	}

	if ((settings = switch_xml_child(cfg, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = NULL;
			char *val = NULL;

			var = (char *) switch_xml_attr_soft(param, "name");
			val = (char *) switch_xml_attr_soft(param, "value");

			if (!strcasecmp(var, "outbound-strategy") && !zstr(val)) {
				default_strategy = parse_strat(val);
			}

			if (!strcasecmp(var, "odbc-dsn") && !zstr(val)) {
				if (switch_odbc_available()) {
					globals.odbc_dsn = switch_core_strdup(globals.pool, val);
					if ((globals.odbc_user = strchr(globals.odbc_dsn, ':'))) {
						*globals.odbc_user++ = '\0';
						if ((globals.odbc_pass = strchr(globals.odbc_user, ':'))) {
							*globals.odbc_pass++ = '\0';
						}
					}
				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "ODBC IS NOT AVAILABLE!\n");
				}
			} else if (!strcasecmp(var, "delete-all-outbound-member-on-startup")) {
				delete_all_outbound_member_on_startup = switch_true(val);
			}
		}
	}

	if (zstr(globals.odbc_dsn)) {
		globals.dbname = "fifo";
	}



	if (!(dbh = fifo_get_db_handle())) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Cannot open DB!\n");
		goto done;
	}

	switch_cache_db_test_reactive(dbh, "delete from fifo_outbound where static = 1 or taking_calls < 0 or manual_calls_in_total_count < 0", "drop table fifo_outbound", outbound_sql);
	switch_cache_db_test_reactive(dbh, "delete from fifo_bridge", "drop table fifo_bridge", bridge_sql);
	switch_cache_db_release_db_handle(&dbh);

	fifo_execute_sql("update fifo_outbound set use_count=0,outbound_call_count=0,outbound_fail_count=0", globals.sql_mutex);

	if (reload) {
		switch_hash_index_t *hi;
		fifo_node_t *node;
		void *val;
		switch_mutex_lock(globals.mutex);
		for (hi = switch_hash_first(NULL, globals.fifo_hash); hi; hi = switch_hash_next(hi)) {
			switch_hash_this(hi, NULL, NULL, &val);
			if ((node = (fifo_node_t *) val) && node->is_static) {
				node->ready = 0;
			}
		}
		switch_mutex_unlock(globals.mutex);
	}

	if ((reload && del_all) || (!reload && delete_all_outbound_member_on_startup)) {
		sql = switch_mprintf("delete from fifo_outbound where hostname='%q'", globals.hostname);
	} else {
		sql = switch_mprintf("delete from fifo_outbound where static=1 and hostname='%q'", globals.hostname);
	}

	fifo_execute_sql(sql, globals.sql_mutex);
	switch_safe_free(sql);

	if (!(node = switch_core_hash_find(globals.fifo_hash, MANUAL_QUEUE_NAME))) {
		node = create_node(MANUAL_QUEUE_NAME, 0, globals.sql_mutex);
		node->is_static = 0;
	}


	if ((fifos = switch_xml_child(cfg, "fifos"))) {
		for (fifo = switch_xml_child(fifos, "fifo"); fifo; fifo = fifo->next) {
			const char *name, *outbound_strategy;
			const char *val;
			int imp = 0, outbound_per_cycle = 1;
			int simo_i = 1;
			int taking_calls_i = 1;
			int timeout_i = 60;
			int lag_i = 10;

			name = switch_xml_attr(fifo, "name");

			if (!name) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "fifo has no name!\n");
				continue;
			}

			if (!strcasecmp(name, MANUAL_QUEUE_NAME)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s is a reserved name, use another name please.\n", MANUAL_QUEUE_NAME);
				continue;
			}
			
			outbound_strategy = switch_xml_attr(fifo, "outbound_strategy");
			

			if ((val = switch_xml_attr(fifo, "importance"))) {
				if ((imp = atoi(val)) < 0) {
					imp = 0;
				}
			}

			if ((val = switch_xml_attr(fifo, "outbound_per_cycle"))) {
				if ((outbound_per_cycle = atoi(val)) < 0) {
					outbound_per_cycle = 0;
				}
			}
			
			switch_mutex_lock(globals.mutex);
			if (!(node = switch_core_hash_find(globals.fifo_hash, name))) {
				node = create_node(name, imp, globals.sql_mutex);
			}

			if ((val = switch_xml_attr(fifo, "outbound_name")) && !zstr(val)) {
				node->outbound_name = switch_core_strdup(node->pool, val);
			}

			switch_mutex_unlock(globals.mutex);

			switch_assert(node);

			switch_mutex_lock(node->mutex);

			node->outbound_per_cycle = outbound_per_cycle;
			

			if (outbound_strategy) {
				node->outbound_strategy = parse_strat(outbound_strategy);
			}

			for (member = switch_xml_child(fifo, "member"); member; member = member->next) {
				const char *simo = switch_xml_attr_soft(member, "simo");
				const char *lag = switch_xml_attr_soft(member, "lag");
				const char *timeout = switch_xml_attr_soft(member, "timeout");
				const char *taking_calls = switch_xml_attr_soft(member, "taking_calls");
				char *name_dup, *p;
				char digest[SWITCH_MD5_DIGEST_STRING_SIZE] = { 0 };

				if (switch_stristr("fifo_outbound_uuid=", member->txt)) {
					extract_fifo_outbound_uuid(member->txt, digest, sizeof(digest));
				} else {
					switch_md5_string(digest, (void *) member->txt, strlen(member->txt));
				}
				
				if (simo) {
					simo_i = atoi(simo);
				}

				if (taking_calls) {
					if ((taking_calls_i = atoi(taking_calls)) < 1) {
						taking_calls_i = 1;
					}
				}

				if (timeout) {
					if ((timeout_i = atoi(timeout)) < 10) {
						timeout_i = 60;
					}

				}

				if (lag) {
					if ((lag_i = atoi(lag)) < 0) {
						lag_i = 10;
					}
				}

				name_dup = strdup(node->name);
				if ((p = strchr(name_dup, '@'))) {
					*p = '\0';
				}


				sql = switch_mprintf("insert into fifo_outbound "
									 "(uuid, fifo_name, originate_string, simo_count, use_count, timeout, lag, "
									 "next_avail, expires, static, outbound_call_count, outbound_fail_count, hostname, taking_calls, "
									 "active_time, inactive_time) "
									 "values ('%q','%q','%q',%d,%d,%d,%d,0,0,1,0,0,'%q',%d,%ld,0)",
									 digest, node->name, member->txt, simo_i, 0, timeout_i, lag_i, globals.hostname, taking_calls_i,
									 (long) switch_epoch_time_now(NULL));
					
				switch_assert(sql);
				fifo_execute_sql(sql, globals.sql_mutex);
				free(sql);
				free(name_dup);
				node->has_outbound = 1;

			}
			node->ready = 1;
			node->is_static = 1;
			switch_mutex_unlock(node->mutex);

			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s configured\n", node->name);

		}
	}
	switch_xml_free(xml);

  done:

	if (reload) {
		switch_hash_index_t *hi;
		void *val;
		switch_event_t *pop;
		fifo_node_t *node;
		switch_mutex_lock(globals.mutex);
	  top:
		for (hi = switch_hash_first(NULL, globals.fifo_hash); hi; hi = switch_hash_next(hi)) {
			int x = 0;
			switch_hash_this(hi, NULL, NULL, &val);
			if (!(node = (fifo_node_t *) val) || !node->is_static || node->ready) {
				continue;
			}

			if (node_consumer_wait_count(node) || node->consumer_count || node_idle_consumers(node)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s removal delayed, still in use.\n", node->name);
				node->ready = FIFO_DELAY_DESTROY;
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "%s removed.\n", node->name);
				switch_thread_rwlock_wrlock(node->rwlock);
				for (x = 0; x < MAX_PRI; x++) {
					while (fifo_queue_pop(node->fifo_list[x], &pop, SWITCH_TRUE) == SWITCH_STATUS_SUCCESS) {
						switch_event_destroy(&pop);
					}
				}

				switch_core_hash_delete(globals.fifo_hash, node->name);
				switch_core_hash_destroy(&node->consumer_hash);
				switch_thread_rwlock_unlock(node->rwlock);
				switch_core_destroy_memory_pool(&node->pool);
				goto top;
			}
		}
		switch_mutex_unlock(globals.mutex);
	}



	return status;
}


static void fifo_member_add(char *fifo_name, char *originate_string, int simo_count, int timeout, int lag, time_t expires, int taking_calls)
{
	char digest[SWITCH_MD5_DIGEST_STRING_SIZE] = { 0 };
	char *sql, *name_dup, *p;
	fifo_node_t *node = NULL;

	if (switch_stristr("fifo_outbound_uuid=", originate_string)) {
		extract_fifo_outbound_uuid(originate_string, digest, sizeof(digest));
	} else {
		switch_md5_string(digest, (void *) originate_string, strlen(originate_string));		
	}

	sql = switch_mprintf("delete from fifo_outbound where fifo_name='%q' and uuid = '%q'", fifo_name, digest);
	switch_assert(sql);
	fifo_execute_sql(sql, globals.sql_mutex);
	free(sql);


	switch_mutex_lock(globals.mutex);
	if (!(node = switch_core_hash_find(globals.fifo_hash, fifo_name))) {
		node = create_node(fifo_name, 0, globals.sql_mutex);
		node->ready = 1;
	}
	switch_mutex_unlock(globals.mutex);

	node->has_outbound = 1;

	name_dup = strdup(fifo_name);
	if ((p = strchr(name_dup, '@'))) {
		*p = '\0';
	}

	sql = switch_mprintf("insert into fifo_outbound "
						 "(uuid, fifo_name, originate_string, simo_count, use_count, timeout, "
						 "lag, next_avail, expires, static, outbound_call_count, outbound_fail_count, hostname, taking_calls, active_time, inactive_time) "
						 "values ('%q','%q','%q',%d,%d,%d,%d,%d,%ld,0,0,0,'%q',%d,%ld,0)",
						 digest, fifo_name, originate_string, simo_count, 0, timeout, lag, 0, (long) expires, globals.hostname, taking_calls,
						 (long)switch_epoch_time_now(NULL));
	switch_assert(sql);
	fifo_execute_sql(sql, globals.sql_mutex);
	free(sql);
	free(name_dup);

}

static void fifo_member_del(char *fifo_name, char *originate_string)
{
	char digest[SWITCH_MD5_DIGEST_STRING_SIZE] = { 0 };
	char *sql;
	char outbound_count[80] = "";
	callback_t cbt = { 0 };
	fifo_node_t *node = NULL;

	if (switch_stristr("fifo_outbound_uuid=", originate_string)) {
		extract_fifo_outbound_uuid(originate_string, digest, sizeof(digest));
	} else {
		switch_md5_string(digest, (void *) originate_string, strlen(originate_string));		
	}

	sql = switch_mprintf("delete from fifo_outbound where fifo_name='%q' and uuid = '%q' and hostname='%q'", fifo_name, digest, globals.hostname);
	switch_assert(sql);
	fifo_execute_sql(sql, globals.sql_mutex);
	free(sql);

	switch_mutex_lock(globals.mutex);
	if (!(node = switch_core_hash_find(globals.fifo_hash, fifo_name))) {
		node = create_node(fifo_name, 0, globals.sql_mutex);
		node->ready = 1;
	}
	switch_mutex_unlock(globals.mutex);

	cbt.buf = outbound_count;
	cbt.len = sizeof(outbound_count);
	sql = switch_mprintf("select count(*) from fifo_outbound where taking_calls = 1 and fifo_name = '%q'", node->name);
	fifo_execute_sql_callback(globals.sql_mutex, sql, sql2str_callback, &cbt);
	if (atoi(outbound_count) > 0) {
        	node->has_outbound = 1;
	} else {
        	node->has_outbound = 0;
	}
	switch_safe_free(sql);	
}

#define FIFO_MEMBER_API_SYNTAX "[add <fifo_name> <originate_string> [<simo_count>] [<timeout>] [<lag>] [<taking_calls>] | del <fifo_name> <originate_string>]"
SWITCH_STANDARD_API(fifo_member_api_function)
{
	char *fifo_name;
	char *originate_string;
	int simo_count = 1;
	int timeout = 60;
	int lag = 5;
	int taking_calls = 1;
	char *action;
	char *mydata = NULL, *argv[8] = { 0 };
	int argc;
	time_t expires = 0;

	if (!globals.running) {
		return SWITCH_STATUS_FALSE;
	}

	if (zstr(cmd)) {
		stream->write_function(stream, "-USAGE: %s\n", FIFO_MEMBER_API_SYNTAX);
		return SWITCH_STATUS_SUCCESS;
	}

	mydata = strdup(cmd);
	switch_assert(mydata);

	argc = switch_separate_string(mydata, ' ', argv, (sizeof(argv) / sizeof(argv[0])));

	if (argc < 3) {
		stream->write_function(stream, "%s", "-ERR Invalid!\n");
		goto done;
	}

	action = argv[0];
	fifo_name = argv[1];
	originate_string = argv[2];

	if (action && !strcasecmp(action, "add")) {
		if (argc > 3) {
			simo_count = atoi(argv[3]);
		}
		if (argc > 4) {
			timeout = atoi(argv[4]);
		}
		if (argc > 5) {
			lag = atoi(argv[5]);
		}
		if (argc > 6) {
			expires = switch_epoch_time_now(NULL) + atoi(argv[6]);
		}
		if (argc > 7) {
			taking_calls = atoi(argv[7]);
		}
		if (simo_count < 0) {
			simo_count = 1;
		}
		if (timeout < 0) {
			timeout = 60;
		}
		if (lag < 0) {
			lag = 5;
		}
		if (taking_calls < 1) {
			taking_calls = 1;
		}

		fifo_member_add(fifo_name, originate_string, simo_count, timeout, lag, expires, taking_calls);
		stream->write_function(stream, "%s", "+OK\n");
	} else if (action && !strcasecmp(action, "del")) {
		fifo_member_del(fifo_name, originate_string);
		stream->write_function(stream, "%s", "+OK\n");
	} else {
		stream->write_function(stream, "%s", "-ERR Invalid!\n");
		goto done;
	}

  done:

	free(mydata);

	return SWITCH_STATUS_SUCCESS;

}

SWITCH_MODULE_LOAD_FUNCTION(mod_fifo_load)
{
	switch_application_interface_t *app_interface;
	switch_api_interface_t *commands_api_interface;
	switch_status_t status;

	/* create/register custom event message type */
	if (switch_event_reserve_subclass(FIFO_EVENT) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't register subclass %s!", FIFO_EVENT);
		return SWITCH_STATUS_TERM;
	}

	/* Subscribe to presence request events */
	if (switch_event_bind_removable(modname, SWITCH_EVENT_PRESENCE_PROBE, SWITCH_EVENT_SUBCLASS_ANY,
									pres_event_handler, NULL, &globals.node) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't subscribe to presence request events!\n");
		return SWITCH_STATUS_GENERR;
	}

	switch_core_new_memory_pool(&globals.pool);
	switch_core_hash_init(&globals.fifo_hash, globals.pool);
	switch_mutex_init(&globals.mutex, SWITCH_MUTEX_NESTED, globals.pool);
	switch_mutex_init(&globals.sql_mutex, SWITCH_MUTEX_NESTED, globals.pool);

	globals.running = 1;

	if ((status = load_config(0, 1)) != SWITCH_STATUS_SUCCESS) {
		switch_event_unbind(&globals.node);
		switch_event_free_subclass(FIFO_EVENT);
		switch_core_hash_destroy(&globals.fifo_hash);
		switch_core_destroy_memory_pool(&globals.pool);
		return status;
	}

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	SWITCH_ADD_APP(app_interface, "fifo", "Park with FIFO", FIFO_DESC, fifo_function, FIFO_USAGE, SAF_NONE);
	SWITCH_ADD_APP(app_interface, "fifo_track_call", "Count a call as a fifo call in the manual_calls queue", 
				   "", fifo_member_usage_function, "<fifo_outbound_uuid>", SAF_SUPPORT_NOMEDIA);
	SWITCH_ADD_API(commands_api_interface, "fifo", "Return data about a fifo", fifo_api_function, FIFO_API_SYNTAX);
	SWITCH_ADD_API(commands_api_interface, "fifo_member", "Add members to a fifo", fifo_member_api_function, FIFO_MEMBER_API_SYNTAX);
	SWITCH_ADD_API(commands_api_interface, "fifo_add_outbound", "Add outbound members to a fifo", fifo_add_outbound_function, "<node> <url> [<priority>]");
	switch_console_set_complete("add fifo list");
	switch_console_set_complete("add fifo list_verbose");
	switch_console_set_complete("add fifo count");
	switch_console_set_complete("add fifo has_outbound");
	switch_console_set_complete("add fifo importance");

	start_node_thread(globals.pool);

	return SWITCH_STATUS_SUCCESS;
}

/*
  Called when the system shuts down 
*/
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_fifo_shutdown)
{
	switch_hash_index_t *hi;
	void *val;
	switch_event_t *pop = NULL;
	fifo_node_t *node;
	switch_memory_pool_t *pool = globals.pool;
	switch_mutex_t *mutex = globals.mutex;

	switch_event_unbind(&globals.node);
	switch_event_free_subclass(FIFO_EVENT);

	switch_mutex_lock(mutex);

	globals.running = 0;
	/* Cleanup */

	if (globals.node_thread_running) {
		stop_node_thread();
	}

	while ((hi = switch_hash_first(NULL, globals.fifo_hash))) {
		int x = 0;
		switch_hash_this(hi, NULL, NULL, &val);
		node = (fifo_node_t *) val;

		switch_thread_rwlock_wrlock(node->rwlock);
		for (x = 0; x < MAX_PRI; x++) {
			while (fifo_queue_pop(node->fifo_list[x], &pop, SWITCH_TRUE) == SWITCH_STATUS_SUCCESS) {
				switch_event_destroy(&pop);
			}
		}

		switch_core_hash_delete(globals.fifo_hash, node->name);
		switch_core_hash_destroy(&node->consumer_hash);
		switch_thread_rwlock_unlock(node->rwlock);
		switch_core_destroy_memory_pool(&node->pool);
	}

	switch_core_hash_destroy(&globals.fifo_hash);
	memset(&globals, 0, sizeof(globals));
	switch_mutex_unlock(mutex);
	switch_core_destroy_memory_pool(&pool);
	return SWITCH_STATUS_SUCCESS;
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
