#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

enum process_event_type {
	PROCESS_EVENT_UNKNOWN = 0,
	PROCESS_EVENT_EXEC = 1,
	PROCESS_EVENT_EXIT = 2,
};

struct process_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u8 event_type;
	__u8 _pad[7];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} process_events SEC(".maps");

static __always_inline int submit_process_event(__u8 event_type)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)(pid_tgid >> 32);
	__u32 tid = (__u32)pid_tgid;
	if (pid != tid) {
		return 0;
	}

	struct process_event *event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid = pid;
	event->tid = tid;
	event->event_type = event_type;
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int process_exec(void *ctx)
{
	return submit_process_event(PROCESS_EVENT_EXEC);
}

SEC("tracepoint/sched/sched_process_exit")
int process_exit(void *ctx)
{
	return submit_process_event(PROCESS_EVENT_EXIT);
}

char _license[] SEC("license") = "GPL";
