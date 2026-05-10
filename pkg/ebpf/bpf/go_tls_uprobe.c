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

struct go_tls_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u64 conn_ptr;
	__u8 probe_kind;
	__u8 _pad[7];
};

struct go_tls_pidns_config {
	__u64 dev;
	__u64 ino;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} go_tls_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct go_tls_pidns_config);
} go_tls_pidns_config_map SEC(".maps");

static __always_inline __u64 go_arg1(struct pt_regs *ctx)
{
#if defined(__TARGET_ARCH_x86)
	return PT_REGS_RC(ctx);
#else
	return PT_REGS_PARM1(ctx);
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

char _license[] SEC("license") = "GPL";
