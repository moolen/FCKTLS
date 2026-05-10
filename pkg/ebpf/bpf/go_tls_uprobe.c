#include <linux/bpf.h>
#include <linux/ptrace.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

enum go_tls_probe_kind {
	GO_TLS_PROBE_KIND_UNKNOWN = 0,
	GO_TLS_PROBE_KIND_CLIENT_HANDSHAKE = 1,
	GO_TLS_PROBE_KIND_SERVER_HANDSHAKE = 2,
	GO_TLS_PROBE_KIND_CONNECTION_STATE = 3,
};

enum go_tls_app_data_direction {
	GO_TLS_APP_DATA_DIRECTION_UNKNOWN = 0,
	GO_TLS_APP_DATA_DIRECTION_READ = 1,
	GO_TLS_APP_DATA_DIRECTION_WRITE = 2,
};

#define GO_TLS_APP_DATA_MAX_LEN 512

struct go_tls_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u64 conn_ptr;
	__u8 probe_kind;
	__u8 _pad[7];
};

struct go_tls_app_data_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u64 conn_ptr;
	__u32 payload_length;
	__u8 direction;
	__u8 _pad[3];
	char payload[GO_TLS_APP_DATA_MAX_LEN];
};

struct go_tls_pidns_config {
	__u64 dev;
	__u64 ino;
};

struct go_tls_app_data_pending {
	__u64 conn_ptr;
	__u64 buffer_ptr;
	__u32 data_len;
	__u8 _pad[4];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} go_tls_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} go_tls_app_data_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct go_tls_pidns_config);
} go_tls_pidns_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct go_tls_app_data_pending);
} go_tls_read_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct go_tls_app_data_pending);
} go_tls_write_pending SEC(".maps");

static __always_inline __u64 go_arg1(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_x86)
	return PT_REGS_RC(ctx);
#else
	return PT_REGS_PARM1(ctx);
#endif
}

static __always_inline __u64 go_arg2(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_x86)
	return ctx->rbx;
#else
	return PT_REGS_PARM2(ctx);
#endif
}

static __always_inline __u64 go_arg3(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_x86)
	return ctx->rcx;
#else
	return PT_REGS_PARM3(ctx);
#endif
}

static __always_inline void current_pid_tgid(__u32 *pid, __u32 *tid)
{
	__u64 current = bpf_get_current_pid_tgid();
	*tid = (__u32)current;
	*pid = (__u32)(current >> 32);

	__u32 key = 0;
	struct go_tls_pidns_config *cfg = bpf_map_lookup_elem(&go_tls_pidns_config_map, &key);
	if (!cfg || !cfg->dev || !cfg->ino) {
		return;
	}

	struct bpf_pidns_info ns = {};
	if (bpf_get_ns_current_pid_tgid(cfg->dev, cfg->ino, &ns, sizeof(ns)) == 0) {
		*pid = ns.tgid;
		*tid = ns.pid;
	}
}

static __always_inline int emit_conn(__u8 kind, __u32 pid, __u32 tid, __u64 conn_ptr)
{
	struct go_tls_event *event = bpf_ringbuf_reserve(&go_tls_events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid = pid;
	event->tid = tid;
	event->conn_ptr = conn_ptr;
	event->probe_kind = kind;
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __always_inline int emit_app_data(const struct go_tls_app_data_pending *pending, __u8 direction, __s64 rc)
{
	__u32 pid = 0;
	__u32 tid = 0;
	__u32 payload_len = (__u32)rc;

	if (rc <= 0) {
		return 0;
	}
	if (payload_len > pending->data_len) {
		payload_len = pending->data_len;
	}
	if (payload_len > GO_TLS_APP_DATA_MAX_LEN) {
		payload_len = GO_TLS_APP_DATA_MAX_LEN;
	}

	current_pid_tgid(&pid, &tid);

	struct go_tls_app_data_event *event = bpf_ringbuf_reserve(&go_tls_app_data_events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid = pid;
	event->tid = tid;
	event->conn_ptr = pending->conn_ptr;
	event->payload_length = payload_len;
	event->direction = direction;
	__builtin_memset(event->payload, 0, sizeof(event->payload));
	if (payload_len > 0) {
		bpf_probe_read_user(event->payload, payload_len, (void *)pending->buffer_ptr);
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("uprobe/client_handshake")
int go_tls_client_handshake_enter(struct pt_regs *ctx)
{
	__u32 pid = 0;
	__u32 tid = 0;
	current_pid_tgid(&pid, &tid);
	__u64 conn_ptr = go_arg1(ctx);
	return emit_conn(GO_TLS_PROBE_KIND_CLIENT_HANDSHAKE, pid, tid, conn_ptr);
}

SEC("uprobe/server_handshake")
int go_tls_server_handshake_enter(struct pt_regs *ctx)
{
	__u32 pid = 0;
	__u32 tid = 0;
	current_pid_tgid(&pid, &tid);
	__u64 conn_ptr = go_arg1(ctx);
	return emit_conn(GO_TLS_PROBE_KIND_SERVER_HANDSHAKE, pid, tid, conn_ptr);
}

SEC("uprobe/connection_state")
int go_tls_connection_state(struct pt_regs *ctx)
{
	__u32 pid = 0;
	__u32 tid = 0;
	current_pid_tgid(&pid, &tid);
	__u64 conn_ptr = go_arg1(ctx);
	return emit_conn(GO_TLS_PROBE_KIND_CONNECTION_STATE, pid, tid, conn_ptr);
}

SEC("uprobe/write")
int go_tls_write_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct go_tls_app_data_pending pending = {};

	pending.conn_ptr = go_arg1(ctx);
	pending.buffer_ptr = go_arg2(ctx);
	pending.data_len = (__u32)go_arg3(ctx);
	bpf_map_update_elem(&go_tls_write_pending, &key, &pending, BPF_ANY);
	return 0;
}

SEC("uretprobe/write")
int go_tls_write_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct go_tls_app_data_pending *pending = bpf_map_lookup_elem(&go_tls_write_pending, &key);

	if (!pending) {
		return 0;
	}
	emit_app_data(pending, GO_TLS_APP_DATA_DIRECTION_WRITE, (__s64)PT_REGS_RC(ctx));
	bpf_map_delete_elem(&go_tls_write_pending, &key);
	return 0;
}

SEC("uprobe/read")
int go_tls_read_enter(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct go_tls_app_data_pending pending = {};

	pending.conn_ptr = go_arg1(ctx);
	pending.buffer_ptr = go_arg2(ctx);
	pending.data_len = (__u32)go_arg3(ctx);
	bpf_map_update_elem(&go_tls_read_pending, &key, &pending, BPF_ANY);
	return 0;
}

SEC("uretprobe/read")
int go_tls_read_return(struct pt_regs *ctx)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct go_tls_app_data_pending *pending = bpf_map_lookup_elem(&go_tls_read_pending, &key);

	if (!pending) {
		return 0;
	}
	emit_app_data(pending, GO_TLS_APP_DATA_DIRECTION_READ, (__s64)PT_REGS_RC(ctx));
	bpf_map_delete_elem(&go_tls_read_pending, &key);
	return 0;
}

char _license[] SEC("license") = "GPL";
