#include <linux/bpf.h>
#include <linux/ptrace.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

enum gnutls_probe_kind {
	GNUTLS_PROBE_KIND_UNKNOWN = 0,
	GNUTLS_PROBE_KIND_HANDSHAKE = 1,
	GNUTLS_PROBE_KIND_TRANSPORT_SET_INT2 = 2,
	GNUTLS_PROBE_KIND_SERVER_NAME_SET = 3,
	GNUTLS_PROBE_KIND_PRIORITY_SET_DIRECT = 4,
	GNUTLS_PROBE_KIND_SESSION_IS_RESUMED = 5,
	GNUTLS_PROBE_KIND_VERIFY_STATUS = 6,
	GNUTLS_PROBE_KIND_GROUP_GET = 7,
	GNUTLS_PROBE_KIND_RECORD_RECV = 8,
	GNUTLS_PROBE_KIND_RECORD_SEND = 9,
};

enum gnutls_event_type {
	GNUTLS_EVENT_TYPE_UNKNOWN = 0,
	GNUTLS_EVENT_TYPE_HANDSHAKE = 1,
	GNUTLS_EVENT_TYPE_SET_FD = 2,
	GNUTLS_EVENT_TYPE_SET_SNI = 3,
	GNUTLS_EVENT_TYPE_SET_PRIORITY = 4,
	GNUTLS_EVENT_TYPE_SESSION_RESUMED = 5,
	GNUTLS_EVENT_TYPE_VERIFY_STATUS = 6,
	GNUTLS_EVENT_TYPE_NEGOTIATED_GROUP = 7,
};

#define GNUTLS_BYTES_MAX_LEN 64
#define GNUTLS_APP_DATA_MAX_LEN 512

enum gnutls_app_data_direction {
	GNUTLS_APP_DATA_DIRECTION_UNKNOWN = 0,
	GNUTLS_APP_DATA_DIRECTION_READ = 1,
	GNUTLS_APP_DATA_DIRECTION_WRITE = 2,
};

struct gnutls_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u64 session_ptr;
	__u64 data_ptr;
	__s32 value;
	__u8 probe_kind;
	__u8 event_type;
	__u8 _pad[2];
	char bytes[GNUTLS_BYTES_MAX_LEN];
};

struct gnutls_app_data_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u64 session_ptr;
	__u32 data_len;
	__u32 payload_length;
	__u8 direction;
	__u8 _pad[3];
	char payload[GNUTLS_APP_DATA_MAX_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} gnutls_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} gnutls_app_data_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u64);
} gnutls_pending SEC(".maps");

struct gnutls_sni_pending {
	__u64 session_ptr;
	__u64 data_ptr;
	char name[GNUTLS_BYTES_MAX_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct gnutls_sni_pending);
} gnutls_sni_pending SEC(".maps");

struct gnutls_priority_pending {
	__u64 session_ptr;
	__u64 data_ptr;
	char priority[GNUTLS_BYTES_MAX_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct gnutls_priority_pending);
} gnutls_priority_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u64);
} gnutls_session_resumed_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u64);
} gnutls_verify_status_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u64);
} gnutls_group_get_pending SEC(".maps");

struct gnutls_app_data_pending {
	__u64 session_ptr;
	__u64 buffer_ptr;
	__u32 data_len;
	__u8 direction;
	__u8 _pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct gnutls_app_data_pending);
} gnutls_app_data_pending SEC(".maps");

static __always_inline void current_pid_tgid(__u32 *pid, __u32 *tid)
{
	__u64 current = bpf_get_current_pid_tgid();
	*tid = (__u32)current;
	*pid = (__u32)(current >> 32);
}

static __always_inline int submit_gnutls_event(__u8 event_type, __u8 probe_kind, __u64 session_ptr, __s32 value, __u64 data_ptr)
{
	__u32 pid = 0;
	__u32 tid = 0;
	current_pid_tgid(&pid, &tid);

	struct gnutls_event *event = bpf_ringbuf_reserve(&gnutls_events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid = pid;
	event->tid = tid;
	event->session_ptr = session_ptr;
	event->data_ptr = data_ptr;
	event->value = value;
	event->probe_kind = probe_kind;
	event->event_type = event_type;
	__builtin_memset(event->bytes, 0, sizeof(event->bytes));
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __always_inline int submit_gnutls_string_event(__u8 event_type, __u8 probe_kind, __u64 session_ptr, __u64 data_ptr, const char value[GNUTLS_BYTES_MAX_LEN])
{
	__u32 pid = 0;
	__u32 tid = 0;
	current_pid_tgid(&pid, &tid);

	struct gnutls_event *event = bpf_ringbuf_reserve(&gnutls_events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid = pid;
	event->tid = tid;
	event->session_ptr = session_ptr;
	event->data_ptr = data_ptr;
	event->value = 0;
	event->probe_kind = probe_kind;
	event->event_type = event_type;
	__builtin_memset(event->bytes, 0, sizeof(event->bytes));
	__builtin_memcpy(event->bytes, value, sizeof(event->bytes));
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __always_inline int submit_gnutls_app_data_event(const struct gnutls_app_data_pending *pending, __s32 rc)
{
	__u32 pid = 0;
	__u32 tid = 0;
	__u32 payload_len = (__u32)rc;
	if (payload_len > pending->data_len) {
		payload_len = pending->data_len;
	}
	if (payload_len > GNUTLS_APP_DATA_MAX_LEN) {
		payload_len = GNUTLS_APP_DATA_MAX_LEN;
	}
	current_pid_tgid(&pid, &tid);

	struct gnutls_app_data_event *event = bpf_ringbuf_reserve(&gnutls_app_data_events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid = pid;
	event->tid = tid;
	event->session_ptr = pending->session_ptr;
	event->data_len = pending->data_len;
	event->payload_length = payload_len;
	event->direction = pending->direction;
	__builtin_memset(event->payload, 0, sizeof(event->payload));
	if (payload_len > 0) {
		bpf_probe_read_user(event->payload, payload_len, (const void *)pending->buffer_ptr);
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("uprobe/gnutls_handshake")
int gnutls_handshake_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 session_ptr = PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&gnutls_pending, &key, &session_ptr, BPF_ANY);
	return 0;
}

SEC("uretprobe/gnutls_handshake")
int gnutls_handshake_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 *session_ptr = bpf_map_lookup_elem(&gnutls_pending, &key);
	if (!session_ptr) {
		return 0;
	}
	submit_gnutls_event(GNUTLS_EVENT_TYPE_HANDSHAKE, GNUTLS_PROBE_KIND_HANDSHAKE, *session_ptr, (__s32)PT_REGS_RC(ctx), 0);
	bpf_map_delete_elem(&gnutls_pending, &key);
	return 0;
}

SEC("uprobe/gnutls_transport_set_int2")
int gnutls_transport_set_int2_enter(struct pt_regs *ctx)
{
	__u64 session_ptr = PT_REGS_PARM1(ctx);
	__s32 recvfd = (__s32)PT_REGS_PARM2(ctx);
	__s32 sendfd = (__s32)PT_REGS_PARM3(ctx);
	__s32 fd = sendfd >= 0 ? sendfd : recvfd;
	return submit_gnutls_event(GNUTLS_EVENT_TYPE_SET_FD, GNUTLS_PROBE_KIND_TRANSPORT_SET_INT2, session_ptr, fd, 0);
}

SEC("uprobe/gnutls_server_name_set")
int gnutls_server_name_set_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct gnutls_sni_pending value = {};
	value.session_ptr = PT_REGS_PARM1(ctx);
	value.data_ptr = PT_REGS_PARM3(ctx);
	bpf_probe_read_user_str(value.name, sizeof(value.name), (const void *)value.data_ptr);
	bpf_map_update_elem(&gnutls_sni_pending, &key, &value, BPF_ANY);
	return 0;
}

SEC("uretprobe/gnutls_server_name_set")
int gnutls_server_name_set_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct gnutls_sni_pending *value = bpf_map_lookup_elem(&gnutls_sni_pending, &key);
	if (!value) {
		return 0;
	}
	if ((__s32)PT_REGS_RC(ctx) >= 0) {
		submit_gnutls_string_event(GNUTLS_EVENT_TYPE_SET_SNI, GNUTLS_PROBE_KIND_SERVER_NAME_SET, value->session_ptr, value->data_ptr, value->name);
	}
	bpf_map_delete_elem(&gnutls_sni_pending, &key);
	return 0;
}

SEC("uprobe/gnutls_priority_set_direct")
int gnutls_priority_set_direct_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct gnutls_priority_pending value = {};
	value.session_ptr = PT_REGS_PARM1(ctx);
	value.data_ptr = PT_REGS_PARM2(ctx);
	bpf_probe_read_user_str(value.priority, sizeof(value.priority), (const void *)value.data_ptr);
	bpf_map_update_elem(&gnutls_priority_pending, &key, &value, BPF_ANY);
	return 0;
}

SEC("uretprobe/gnutls_priority_set_direct")
int gnutls_priority_set_direct_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct gnutls_priority_pending *value = bpf_map_lookup_elem(&gnutls_priority_pending, &key);
	if (!value) {
		return 0;
	}
	if ((__s32)PT_REGS_RC(ctx) >= 0) {
		submit_gnutls_string_event(GNUTLS_EVENT_TYPE_SET_PRIORITY, GNUTLS_PROBE_KIND_PRIORITY_SET_DIRECT, value->session_ptr, value->data_ptr, value->priority);
	}
	bpf_map_delete_elem(&gnutls_priority_pending, &key);
	return 0;
}

SEC("uprobe/gnutls_session_is_resumed")
int gnutls_session_is_resumed_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 session_ptr = PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&gnutls_session_resumed_pending, &key, &session_ptr, BPF_ANY);
	return 0;
}

SEC("uretprobe/gnutls_session_is_resumed")
int gnutls_session_is_resumed_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 *session_ptr = bpf_map_lookup_elem(&gnutls_session_resumed_pending, &key);
	if (!session_ptr) {
		return 0;
	}
	submit_gnutls_event(GNUTLS_EVENT_TYPE_SESSION_RESUMED, GNUTLS_PROBE_KIND_SESSION_IS_RESUMED, *session_ptr, (__s32)PT_REGS_RC(ctx), 0);
	bpf_map_delete_elem(&gnutls_session_resumed_pending, &key);
	return 0;
}

SEC("uprobe/gnutls_session_get_verify_cert_status")
int gnutls_session_get_verify_cert_status_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 session_ptr = PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&gnutls_verify_status_pending, &key, &session_ptr, BPF_ANY);
	return 0;
}

SEC("uretprobe/gnutls_session_get_verify_cert_status")
int gnutls_session_get_verify_cert_status_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 *session_ptr = bpf_map_lookup_elem(&gnutls_verify_status_pending, &key);
	if (!session_ptr) {
		return 0;
	}
	submit_gnutls_event(GNUTLS_EVENT_TYPE_VERIFY_STATUS, GNUTLS_PROBE_KIND_VERIFY_STATUS, *session_ptr, (__s32)PT_REGS_RC(ctx), 0);
	bpf_map_delete_elem(&gnutls_verify_status_pending, &key);
	return 0;
}

SEC("uprobe/gnutls_group_get")
int gnutls_group_get_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 session_ptr = PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&gnutls_group_get_pending, &key, &session_ptr, BPF_ANY);
	return 0;
}

SEC("uretprobe/gnutls_group_get")
int gnutls_group_get_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 *session_ptr = bpf_map_lookup_elem(&gnutls_group_get_pending, &key);
	if (!session_ptr) {
		return 0;
	}
	submit_gnutls_event(GNUTLS_EVENT_TYPE_NEGOTIATED_GROUP, GNUTLS_PROBE_KIND_GROUP_GET, *session_ptr, (__s32)PT_REGS_RC(ctx), 0);
	bpf_map_delete_elem(&gnutls_group_get_pending, &key);
	return 0;
}

SEC("uprobe/gnutls_record_recv")
int gnutls_record_recv_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct gnutls_app_data_pending value = {};
	value.session_ptr = PT_REGS_PARM1(ctx);
	value.buffer_ptr = PT_REGS_PARM2(ctx);
	value.data_len = (__u32)PT_REGS_PARM3(ctx);
	value.direction = GNUTLS_APP_DATA_DIRECTION_READ;
	bpf_map_update_elem(&gnutls_app_data_pending, &key, &value, BPF_ANY);
	return 0;
}

SEC("uretprobe/gnutls_record_recv")
int gnutls_record_recv_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct gnutls_app_data_pending *pending = bpf_map_lookup_elem(&gnutls_app_data_pending, &key);
	if (!pending) {
		return 0;
	}

	__s32 rc = (__s32)PT_REGS_RC(ctx);
	if (rc > 0) {
		submit_gnutls_app_data_event(pending, rc);
	}
	bpf_map_delete_elem(&gnutls_app_data_pending, &key);
	return 0;
}

SEC("uprobe/gnutls_record_send")
int gnutls_record_send_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct gnutls_app_data_pending value = {};
	value.session_ptr = PT_REGS_PARM1(ctx);
	value.buffer_ptr = PT_REGS_PARM2(ctx);
	value.data_len = (__u32)PT_REGS_PARM3(ctx);
	value.direction = GNUTLS_APP_DATA_DIRECTION_WRITE;
	bpf_map_update_elem(&gnutls_app_data_pending, &key, &value, BPF_ANY);
	return 0;
}

SEC("uretprobe/gnutls_record_send")
int gnutls_record_send_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct gnutls_app_data_pending *pending = bpf_map_lookup_elem(&gnutls_app_data_pending, &key);
	if (!pending) {
		return 0;
	}

	__s32 rc = (__s32)PT_REGS_RC(ctx);
	if (rc > 0) {
		submit_gnutls_app_data_event(pending, rc);
	}
	bpf_map_delete_elem(&gnutls_app_data_pending, &key);
	return 0;
}

char _license[] SEC("license") = "GPL";
