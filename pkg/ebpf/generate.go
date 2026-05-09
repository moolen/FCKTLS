//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86" process_events ./bpf/process_events.c -- -I./bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86" openssl_uprobe ./bpf/openssl_uprobe.c -- -I./bpf

package ebpf
