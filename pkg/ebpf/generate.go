//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" process_events ./bpf/process_events.c -- -I./bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" openssl_uprobe ./bpf/openssl_uprobe.c -- -I./bpf

package ebpf
