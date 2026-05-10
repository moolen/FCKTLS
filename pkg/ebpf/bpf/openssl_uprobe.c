#include <linux/bpf.h>
#include <linux/ptrace.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

enum openssl_probe_kind {
	OPENSSL_PROBE_KIND_UNKNOWN = 0,
	OPENSSL_PROBE_KIND_SSL_CONNECT = 1,
	OPENSSL_PROBE_KIND_SSL_ACCEPT = 2,
	OPENSSL_PROBE_KIND_SSL_DO_HANDSHAKE = 3,
};

enum openssl_event_type {
	OPENSSL_EVENT_TYPE_UNKNOWN = 0,
	OPENSSL_EVENT_TYPE_HANDSHAKE = 1,
	OPENSSL_EVENT_TYPE_SET_FD = 2,
	OPENSSL_EVENT_TYPE_SET_SNI = 3,
	OPENSSL_EVENT_TYPE_SET_GROUPS = 4,
	OPENSSL_EVENT_TYPE_SET_VERIFY = 5,
	OPENSSL_EVENT_TYPE_SESSION_REUSED = 6,
	OPENSSL_EVENT_TYPE_VERIFY_RESULT = 7,
	OPENSSL_EVENT_TYPE_NEGOTIATED_GROUP = 8,
	OPENSSL_EVENT_TYPE_KEY_MATERIAL = 9,
};

enum openssl_app_data_direction {
	OPENSSL_APP_DATA_DIRECTION_UNKNOWN = 0,
	OPENSSL_APP_DATA_DIRECTION_READ = 1,
	OPENSSL_APP_DATA_DIRECTION_WRITE = 2,
};

#define OPENSSL_SNI_MAX_LEN 64
#define OPENSSL_CLIENT_RANDOM_LEN 32
#define OPENSSL_SECRET_MAX_LEN 64
#define OPENSSL_APP_DATA_MAX_LEN 512
#define OPENSSL_KEYLOG_HELPER_CLIENT_RANDOM_OFFSET 0x160

struct openssl_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u64 session_ptr;
	__u64 data_ptr;
	__s32 value;
	__u8 probe_kind;
	__u8 event_type;
	__u8 client_random_length;
	__u8 secret_length;
	char sni[OPENSSL_SNI_MAX_LEN];
	unsigned char client_random[OPENSSL_CLIENT_RANDOM_LEN];
	unsigned char secret[OPENSSL_SECRET_MAX_LEN];
};

struct openssl_app_data_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u64 session_ptr;
	__u32 data_len;
	__u32 payload_length;
	__u8 direction;
	__u8 _pad[3];
	char payload[OPENSSL_APP_DATA_MAX_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} openssl_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} openssl_app_data_events SEC(".maps");

struct openssl_pending_key {
	__u64 pid_tgid;
	__u8 probe_kind;
	__u8 _pad[7];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct openssl_pending_key);
	__type(value, __u64);
} openssl_pending SEC(".maps");

struct openssl_fd_pending {
	__u64 session_ptr;
	__s32 fd;
	__u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct openssl_fd_pending);
} openssl_fd_pending SEC(".maps");

struct openssl_sni_pending {
	__u64 session_ptr;
	char name[OPENSSL_SNI_MAX_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct openssl_sni_pending);
} openssl_sni_pending SEC(".maps");

struct openssl_groups_pending {
	__u64 session_ptr;
	char groups[OPENSSL_SNI_MAX_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct openssl_groups_pending);
} openssl_groups_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u64);
} openssl_session_reused_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u64);
} openssl_verify_result_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u64);
} openssl_negotiated_group_pending SEC(".maps");

struct openssl_app_data_pending {
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
	__type(value, struct openssl_app_data_pending);
} openssl_app_data_pending SEC(".maps");

static __always_inline void current_pid_tgid(__u32 *pid, __u32 *tid)
{
	__u64 current = bpf_get_current_pid_tgid();
	*tid = (__u32)current;
	*pid = (__u32)(current >> 32);
}

static __always_inline int submit_openssl_event(__u8 event_type, __u8 probe_kind, __u64 session_ptr, __s32 value, __u64 data_ptr)
{
	__u32 pid = 0;
	__u32 tid = 0;
	current_pid_tgid(&pid, &tid);
	struct openssl_event *event = bpf_ringbuf_reserve(&openssl_events, sizeof(*event), 0);
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
	__builtin_memset(event->sni, 0, sizeof(event->sni));
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __always_inline int submit_openssl_string_event(__u8 event_type, __u64 session_ptr, const char value[OPENSSL_SNI_MAX_LEN])
{
	__u32 pid = 0;
	__u32 tid = 0;
	current_pid_tgid(&pid, &tid);
	struct openssl_event *event = bpf_ringbuf_reserve(&openssl_events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid = pid;
	event->tid = tid;
	event->session_ptr = session_ptr;
	event->data_ptr = 0;
	event->value = 0;
	event->probe_kind = OPENSSL_PROBE_KIND_UNKNOWN;
	event->event_type = event_type;
	__builtin_memset(event->sni, 0, sizeof(event->sni));
	__builtin_memcpy(event->sni, value, sizeof(event->sni));
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __always_inline int submit_openssl_key_material_event(__u64 session_ptr, const char *label_ptr, const unsigned char *secret_ptr, __u64 secret_len)
{
	__u32 pid = 0;
	__u32 tid = 0;
	__u8 capped_secret_len = secret_len > OPENSSL_SECRET_MAX_LEN ? OPENSSL_SECRET_MAX_LEN : (__u8)secret_len;
	current_pid_tgid(&pid, &tid);

	struct openssl_event *event = bpf_ringbuf_reserve(&openssl_events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid = pid;
	event->tid = tid;
	event->session_ptr = session_ptr;
	event->data_ptr = 0;
	event->value = 0;
	event->probe_kind = OPENSSL_PROBE_KIND_UNKNOWN;
	event->event_type = OPENSSL_EVENT_TYPE_KEY_MATERIAL;
	event->client_random_length = OPENSSL_CLIENT_RANDOM_LEN;
	event->secret_length = capped_secret_len;
	__builtin_memset(event->sni, 0, sizeof(event->sni));
	__builtin_memset(event->client_random, 0, sizeof(event->client_random));
	__builtin_memset(event->secret, 0, sizeof(event->secret));
	bpf_probe_read_user_str(event->sni, OPENSSL_CLIENT_RANDOM_LEN, label_ptr);
	bpf_probe_read_user(event->client_random, OPENSSL_CLIENT_RANDOM_LEN, (void *)(session_ptr + OPENSSL_KEYLOG_HELPER_CLIENT_RANDOM_OFFSET));
	if (capped_secret_len > 0) {
		bpf_probe_read_user(event->secret, capped_secret_len, secret_ptr);
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __always_inline int submit_openssl_sni_event(__u64 session_ptr, const struct openssl_sni_pending *pending)
{
	return submit_openssl_string_event(OPENSSL_EVENT_TYPE_SET_SNI, session_ptr, pending->name);
}

static __always_inline int submit_openssl_app_data_event(const struct openssl_app_data_pending *pending, __s32 rc)
{
	__u32 pid = 0;
	__u32 tid = 0;
	__u32 payload_len = (__u32)rc;
	current_pid_tgid(&pid, &tid);
	if (payload_len > pending->data_len) {
		payload_len = pending->data_len;
	}
	if (payload_len > OPENSSL_APP_DATA_MAX_LEN) {
		payload_len = OPENSSL_APP_DATA_MAX_LEN;
	}

	struct openssl_app_data_event *event = bpf_ringbuf_reserve(&openssl_app_data_events, sizeof(*event), 0);
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
	if (payload_len > 0) {
		bpf_probe_read_user(event->payload, payload_len, (void *)pending->buffer_ptr);
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __always_inline int openssl_enter(struct pt_regs *ctx, __u8 probe_kind)
{
	struct openssl_pending_key key = {};
	key.pid_tgid = bpf_get_current_pid_tgid();
	key.probe_kind = probe_kind;

	__u64 session_ptr = PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&openssl_pending, &key, &session_ptr, BPF_ANY);
	return 0;
}

static __always_inline int openssl_return(struct pt_regs *ctx, __u8 probe_kind)
{
	struct openssl_pending_key key = {};
	key.pid_tgid = bpf_get_current_pid_tgid();
	key.probe_kind = probe_kind;

	__u64 *session_ptr = bpf_map_lookup_elem(&openssl_pending, &key);
	if (!session_ptr) {
		return 0;
	}
	submit_openssl_event(OPENSSL_EVENT_TYPE_HANDSHAKE, probe_kind, *session_ptr, (__s32)PT_REGS_RC(ctx), 0);
	bpf_map_delete_elem(&openssl_pending, &key);
	return 0;
}

SEC("uprobe/SSL_connect")
int openssl_ssl_connect_enter(struct pt_regs *ctx)
{
	return openssl_enter(ctx, OPENSSL_PROBE_KIND_SSL_CONNECT);
}

SEC("uretprobe/SSL_connect")
int openssl_ssl_connect_return(struct pt_regs *ctx)
{
	return openssl_return(ctx, OPENSSL_PROBE_KIND_SSL_CONNECT);
}

SEC("uprobe/SSL_accept")
int openssl_ssl_accept_enter(struct pt_regs *ctx)
{
	return openssl_enter(ctx, OPENSSL_PROBE_KIND_SSL_ACCEPT);
}

SEC("uretprobe/SSL_accept")
int openssl_ssl_accept_return(struct pt_regs *ctx)
{
	return openssl_return(ctx, OPENSSL_PROBE_KIND_SSL_ACCEPT);
}

SEC("uprobe/SSL_do_handshake")
int openssl_ssl_do_handshake_enter(struct pt_regs *ctx)
{
	return openssl_enter(ctx, OPENSSL_PROBE_KIND_SSL_DO_HANDSHAKE);
}

SEC("uretprobe/SSL_do_handshake")
int openssl_ssl_do_handshake_return(struct pt_regs *ctx)
{
	return openssl_return(ctx, OPENSSL_PROBE_KIND_SSL_DO_HANDSHAKE);
}

SEC("uprobe/openssl_keylog_secret")
int openssl_ssl_keylog_secret_enter(struct pt_regs *ctx)
{
	__u64 session_ptr = PT_REGS_PARM1(ctx);
	const char *label_ptr = (const char *)PT_REGS_PARM2(ctx);
	const unsigned char *secret_ptr = (const unsigned char *)PT_REGS_PARM3(ctx);
	__u64 secret_len = PT_REGS_PARM4(ctx);
	if (session_ptr == 0 || label_ptr == 0 || secret_ptr == 0 || secret_len == 0) {
		return 0;
	}
	return submit_openssl_key_material_event(session_ptr, label_ptr, secret_ptr, secret_len);
}

SEC("uprobe/SSL_set_fd")
int openssl_ssl_set_fd_enter(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct openssl_fd_pending value = {};
	value.session_ptr = PT_REGS_PARM1(ctx);
	value.fd = (__s32)PT_REGS_PARM2(ctx);
	bpf_map_update_elem(&openssl_fd_pending, &pid_tgid, &value, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_set_fd")
int openssl_ssl_set_fd_return(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct openssl_fd_pending *pending = bpf_map_lookup_elem(&openssl_fd_pending, &pid_tgid);
	if (!pending) {
		return 0;
	}
	if ((__s32)PT_REGS_RC(ctx) > 0) {
		submit_openssl_event(OPENSSL_EVENT_TYPE_SET_FD, OPENSSL_PROBE_KIND_UNKNOWN, pending->session_ptr, pending->fd, 0);
	}
	bpf_map_delete_elem(&openssl_fd_pending, &pid_tgid);
	return 0;
}

#define OPENSSL_SSL_CTRL_SET_TLSEXT_HOSTNAME 55

SEC("uprobe/SSL_ctrl")
int openssl_ssl_ctrl_enter(struct pt_regs *ctx)
{
	if ((__s32)PT_REGS_PARM2(ctx) != OPENSSL_SSL_CTRL_SET_TLSEXT_HOSTNAME) {
		return 0;
	}
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct openssl_sni_pending value = {};
	value.session_ptr = PT_REGS_PARM1(ctx);
	bpf_probe_read_user_str(value.name, sizeof(value.name), (const void *)PT_REGS_PARM4(ctx));
	bpf_map_update_elem(&openssl_sni_pending, &pid_tgid, &value, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_ctrl")
int openssl_ssl_ctrl_return(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct openssl_sni_pending *pending = bpf_map_lookup_elem(&openssl_sni_pending, &pid_tgid);
	if (!pending) {
		return 0;
	}
	if ((__s32)PT_REGS_RC(ctx) > 0) {
		submit_openssl_sni_event(pending->session_ptr, pending);
	}
	bpf_map_delete_elem(&openssl_sni_pending, &pid_tgid);
	return 0;
}

SEC("uprobe/SSL_set1_groups_list")
int openssl_ssl_set_groups_list_enter(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct openssl_groups_pending value = {};
	value.session_ptr = PT_REGS_PARM1(ctx);
	bpf_probe_read_user_str(value.groups, sizeof(value.groups), (const void *)PT_REGS_PARM2(ctx));
	bpf_map_update_elem(&openssl_groups_pending, &pid_tgid, &value, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_set1_groups_list")
int openssl_ssl_set_groups_list_return(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct openssl_groups_pending *pending = bpf_map_lookup_elem(&openssl_groups_pending, &pid_tgid);
	if (!pending) {
		return 0;
	}
	if ((__s32)PT_REGS_RC(ctx) > 0) {
		submit_openssl_string_event(OPENSSL_EVENT_TYPE_SET_GROUPS, pending->session_ptr, pending->groups);
	}
	bpf_map_delete_elem(&openssl_groups_pending, &pid_tgid);
	return 0;
}

SEC("uprobe/SSL_set_verify")
int openssl_ssl_set_verify_enter(struct pt_regs *ctx)
{
	return submit_openssl_event(OPENSSL_EVENT_TYPE_SET_VERIFY, OPENSSL_PROBE_KIND_UNKNOWN, PT_REGS_PARM1(ctx), (__s32)PT_REGS_PARM2(ctx), 0);
}

SEC("uprobe/SSL_session_reused")
int openssl_ssl_session_reused_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 value = PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&openssl_session_reused_pending, &key, &value, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_session_reused")
int openssl_ssl_session_reused_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 *session_ptr = bpf_map_lookup_elem(&openssl_session_reused_pending, &key);
	if (!session_ptr) {
		return 0;
	}
	submit_openssl_event(OPENSSL_EVENT_TYPE_SESSION_REUSED, OPENSSL_PROBE_KIND_UNKNOWN, *session_ptr, (__s32)PT_REGS_RC(ctx), 0);
	bpf_map_delete_elem(&openssl_session_reused_pending, &key);
	return 0;
}

SEC("uprobe/SSL_get_verify_result")
int openssl_ssl_get_verify_result_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 value = PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&openssl_verify_result_pending, &key, &value, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_get_verify_result")
int openssl_ssl_get_verify_result_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 *session_ptr = bpf_map_lookup_elem(&openssl_verify_result_pending, &key);
	if (!session_ptr) {
		return 0;
	}
	submit_openssl_event(OPENSSL_EVENT_TYPE_VERIFY_RESULT, OPENSSL_PROBE_KIND_UNKNOWN, *session_ptr, (__s32)PT_REGS_RC(ctx), 0);
	bpf_map_delete_elem(&openssl_verify_result_pending, &key);
	return 0;
}

SEC("uprobe/SSL_get_negotiated_group")
int openssl_ssl_get_negotiated_group_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 value = PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&openssl_negotiated_group_pending, &key, &value, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_get_negotiated_group")
int openssl_ssl_get_negotiated_group_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	__u64 *session_ptr = bpf_map_lookup_elem(&openssl_negotiated_group_pending, &key);
	if (!session_ptr) {
		return 0;
	}
	submit_openssl_event(OPENSSL_EVENT_TYPE_NEGOTIATED_GROUP, OPENSSL_PROBE_KIND_UNKNOWN, *session_ptr, (__s32)PT_REGS_RC(ctx), 0);
	bpf_map_delete_elem(&openssl_negotiated_group_pending, &key);
	return 0;
}

SEC("uprobe/SSL_read")
int openssl_ssl_read_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct openssl_app_data_pending value = {};
	value.session_ptr = PT_REGS_PARM1(ctx);
	value.buffer_ptr = PT_REGS_PARM2(ctx);
	value.data_len = (__u32)PT_REGS_PARM3(ctx);
	value.direction = OPENSSL_APP_DATA_DIRECTION_READ;
	bpf_map_update_elem(&openssl_app_data_pending, &key, &value, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_read")
int openssl_ssl_read_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct openssl_app_data_pending *pending = bpf_map_lookup_elem(&openssl_app_data_pending, &key);
	if (!pending) {
		return 0;
	}
	__s32 rc = (__s32)PT_REGS_RC(ctx);
	if (rc > 0) {
		submit_openssl_app_data_event(pending, rc);
	}
	bpf_map_delete_elem(&openssl_app_data_pending, &key);
	return 0;
}

SEC("uprobe/SSL_write")
int openssl_ssl_write_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct openssl_app_data_pending value = {};
	value.session_ptr = PT_REGS_PARM1(ctx);
	value.buffer_ptr = PT_REGS_PARM2(ctx);
	value.data_len = (__u32)PT_REGS_PARM3(ctx);
	value.direction = OPENSSL_APP_DATA_DIRECTION_WRITE;
	bpf_map_update_elem(&openssl_app_data_pending, &key, &value, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_write")
int openssl_ssl_write_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct openssl_app_data_pending *pending = bpf_map_lookup_elem(&openssl_app_data_pending, &key);
	if (!pending) {
		return 0;
	}
	__s32 rc = (__s32)PT_REGS_RC(ctx);
	if (rc > 0) {
		submit_openssl_app_data_event(pending, rc);
	}
	bpf_map_delete_elem(&openssl_app_data_pending, &key);
	return 0;
}

char _license[] SEC("license") = "GPL";
