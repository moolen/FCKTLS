# FCKTLS Go TLS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Go `crypto/tls` runtime slice to `fcktls` that matches basename-targeted Go clients, stops supported processes on exec, attaches per-PID Go TLS uprobes, emits negotiated metadata and best-effort keys, and reuses the existing session/render/artifact model.

**Architecture:** Reuse `../cmon`’s Go TLS eBPF and executable-inspection work, but adapt it to FCKTLS’s daemon/session pipeline and add a narrow stop-on-exec gate for short-lived Go processes. Keep plaintext capture explicitly deferred; this slice is metadata-first and builds the control plane needed for Go plaintext later.

**Tech Stack:** Go 1.24, `cilium/ebpf`, Linux uprobes, `ptrace` or `SIGSTOP`/`SIGCONT` process gating, `debug/buildinfo`, ELF symbol inspection, root-only Go integration tests.

---

### Task 1: Add Go TLS eBPF Loader And Attach Surface

**Files:**
- Create: `pkg/ebpf/go_tls.go`
- Create: `pkg/ebpf/go_tls_test.go`
- Create: `pkg/ebpf/bpf/go_tls_uprobe.c`
- Modify: `pkg/ebpf/generate.go`

- [ ] **Step 1: Write failing decode and attach-spec tests in `pkg/ebpf/go_tls_test.go`**

```go
func TestDecodeGoTLSEvent(t *testing.T) {
	raw := make([]byte, goTLSEventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 123)
	binary.LittleEndian.PutUint32(raw[8:12], 4242)
	binary.LittleEndian.PutUint32(raw[12:16], 4343)
	binary.LittleEndian.PutUint64(raw[16:24], 0xfeedbeef)
	raw[24] = byte(GoTLSProbeKindClientHandshake)

	event, err := decodeGoTLSEvent(raw)
	if err != nil {
		t.Fatalf("decodeGoTLSEvent() error = %v", err)
	}
	if got, want := event.ProbeKind, GoTLSProbeKindClientHandshake; got != want {
		t.Fatalf("ProbeKind = %d, want %d", got, want)
	}
}

func TestGoTLSAttachSpecs(t *testing.T) {
	specs := goTLSUprobeAttachSpecs(goTLSObjects{})
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		names = append(names, spec.symbol)
	}
	for _, want := range []string{
		"crypto/tls.(*Conn).clientHandshake",
		"crypto/tls.(*Conn).serverHandshake",
		"crypto/tls.(*Conn).ConnectionState",
	} {
		if !slices.Contains(names, want) {
			t.Fatalf("attach specs missing %q", want)
		}
	}
}
```

- [ ] **Step 2: Run the focused `pkg/ebpf` tests and verify they fail**

Run: `/usr/local/go/bin/go test ./pkg/ebpf -run 'Test(DecodeGoTLSEvent|GoTLSAttachSpecs)' -v`

Expected: `FAIL` with undefined `GoTLSEvent`, `decodeGoTLSEvent`, `goTLSUprobeAttachSpecs`, or missing object references.

- [ ] **Step 3: Implement the minimal Go TLS loader and BPF surface**

```go
type GoTLSProbeKind uint8

const (
	GoTLSProbeKindUnknown GoTLSProbeKind = iota
	GoTLSProbeKindClientHandshake
	GoTLSProbeKindServerHandshake
	GoTLSProbeKindConnectionState
)

type GoTLSEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	ConnPtr     uint64
	ProbeKind   GoTLSProbeKind
	_           [7]byte
}
```

```c
SEC("uprobe/client_handshake")
int go_tls_client_handshake_enter(struct pt_regs *ctx) { ... }

SEC("uprobe/server_handshake")
int go_tls_server_handshake_enter(struct pt_regs *ctx) { ... }

SEC("uprobe/connection_state")
int go_tls_connection_state(struct pt_regs *ctx) { ... }
```

- [ ] **Step 4: Add the generate directive and regenerate objects**

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86" go_tls_uprobe ./bpf/go_tls_uprobe.c -- -I./bpf
```

- [ ] **Step 5: Run the focused `pkg/ebpf` tests again and verify they pass**

Run: `/usr/local/go/bin/go test ./pkg/ebpf -run 'Test(DecodeGoTLSEvent|GoTLSAttachSpecs)' -v`

Expected: `PASS`

- [ ] **Step 6: Commit the loader/BPF slice**

```bash
git add pkg/ebpf/go_tls.go pkg/ebpf/go_tls_test.go pkg/ebpf/bpf/go_tls_uprobe.c pkg/ebpf/generate.go
git commit -m "feat: add go tls ebpf loader"
```

### Task 2: Add Go Binary Inspection And Symbol Gating

**Files:**
- Create: `pkg/fcktls/go_binary_inspector.go`
- Create: `pkg/fcktls/go_binary_inspector_test.go`

- [ ] **Step 1: Write failing tests for Go executable detection and required-symbol gating**

```go
func TestInspectGoBinaryRejectsMissingTLSSymbols(t *testing.T) {
	info := goBinaryInspection{
		IsGoBinary: true,
		Symbols: map[string]struct{}{
			"main.main": {},
		},
	}
	if info.SupportsCryptoTLS() {
		t.Fatal("SupportsCryptoTLS() = true, want false")
	}
}

func TestInspectGoBinaryAcceptsRequiredTLSSymbols(t *testing.T) {
	info := goBinaryInspection{
		IsGoBinary: true,
		Symbols: map[string]struct{}{
			"crypto/tls.(*Conn).clientHandshake": {},
			"crypto/tls.(*Conn).serverHandshake": {},
			"crypto/tls.(*Conn).ConnectionState": {},
		},
	}
	if !info.SupportsCryptoTLS() {
		t.Fatal("SupportsCryptoTLS() = false, want true")
	}
}
```

- [ ] **Step 2: Run the focused inspection tests and verify they fail**

Run: `/usr/local/go/bin/go test ./pkg/fcktls -run 'TestInspectGoBinary' -v`

Expected: `FAIL` with undefined inspection types or methods.

- [ ] **Step 3: Implement Go executable inspection adapted from `../cmon`**

The inspector should:

- read Go build info
- read ELF symbols
- determine whether the binary is Go
- verify the required `crypto/tls.(*Conn)` symbols are present
- expose enough metadata for the exec gate and daemon

- [ ] **Step 4: Run the focused tests again and verify they pass**

Run: `/usr/local/go/bin/go test ./pkg/fcktls -run 'TestInspectGoBinary' -v`

Expected: `PASS`

- [ ] **Step 5: Commit the inspection slice**

```bash
git add pkg/fcktls/go_binary_inspector.go pkg/fcktls/go_binary_inspector_test.go
git commit -m "feat: add go binary inspection"
```

### Task 3: Add Stop-On-Exec Go Attach Gating In The Daemon

**Files:**
- Create: `pkg/fcktls/go_exec_gate.go`
- Create: `pkg/fcktls/go_exec_gate_test.go`
- Modify: `pkg/fcktls/daemon.go`
- Modify: `pkg/fcktls/daemon_test.go`

- [ ] **Step 1: Write failing tests for matched Go exec attach/resume behavior**

```go
func TestGoExecGateStopsAttachesAndResumesSupportedProcess(t *testing.T) {
	gate := &GoExecGate{
		StopProcess:   func(pid int) error { return nil },
		ResumeProcess: func(pid int) error { return nil },
		Inspect: func(pid int, exe string) (goBinaryInspection, error) {
			return goBinaryInspection{
				IsGoBinary: true,
				Symbols: map[string]struct{}{
					"crypto/tls.(*Conn).clientHandshake": {},
					"crypto/tls.(*Conn).serverHandshake": {},
					"crypto/tls.(*Conn).ConnectionState": {},
				},
			}, nil
		},
	}
}
```

- [ ] **Step 2: Run the focused gate/daemon tests and verify they fail**

Run: `/usr/local/go/bin/go test ./pkg/fcktls -run 'Test(GoExecGate|Daemon.*GoTLS)' -v`

Expected: `FAIL` with undefined Go exec gate behavior or daemon wiring.

- [ ] **Step 3: Implement a narrow stop-on-exec controller and daemon wiring**

The daemon changes should:

- add a Go TLS loader
- invoke Go binary inspection on matched execs
- stop the process when the binary supports Go `crypto/tls`
- attach the Go TLS uprobes per PID
- always resume the process
- keep non-Go or unsupported targets on the existing paths

- [ ] **Step 4: Run the focused tests again and verify they pass**

Run: `/usr/local/go/bin/go test ./pkg/fcktls -run 'Test(GoExecGate|Daemon.*GoTLS)' -v`

Expected: `PASS`

- [ ] **Step 5: Run the package regression tests**

Run: `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go test ./pkg/fcktls`

Expected: `ok   github.com/moolen/FCKTLS/pkg/fcktls`

- [ ] **Step 6: Commit the exec-gate slice**

```bash
git add pkg/fcktls/go_exec_gate.go pkg/fcktls/go_exec_gate_test.go pkg/fcktls/daemon.go pkg/fcktls/daemon_test.go
git commit -m "feat: add go tls exec gating"
```

### Task 4: Add Go TLS Metadata Extraction And Session Integration

**Files:**
- Create: `pkg/fcktls/go_tls_inspector_linux.go`
- Create: `pkg/fcktls/go_tls_inspector_linux_test.go`
- Modify: `pkg/fcktls/daemon.go`
- Modify: `pkg/fcktls/types.go`
- Modify: `pkg/fcktls/session_store.go`
- Modify: `pkg/fcktls/render.go`
- Modify: `pkg/fcktls/artifacts.go`
- Modify: `pkg/fcktls/daemon_test.go`

- [ ] **Step 1: Write failing tests for Go TLS metadata merge**

```go
func TestDaemonMergesGoTLSMetadata(t *testing.T) {
	cfg, _ := NewConfig("go-client", false, t.TempDir())
	d := &Daemon{Config: cfg, Store: NewSessionStore(), Stdout: io.Discard}

	tracked := map[int]ProcessMatch{
		909: {PID: 909, ExePath: "/tmp/go-client", Basename: "go-client"},
	}
	seen := map[int]bool{909: false}
	fds := make(map[SessionKey]int)

	d.handleGoTLSEvent(ebpf.GoTLSEvent{
		PID:      909,
		ConnPtr:  0x9,
		ProbeKind: ebpf.GoTLSProbeKindConnectionState,
	}, tracked, seen, fds)
}
```

- [ ] **Step 2: Run the focused Go TLS metadata tests and verify they fail**

Run: `/usr/local/go/bin/go test ./pkg/fcktls -run 'TestDaemon.*GoTLSMetadata' -v`

Expected: `FAIL` with missing Go TLS metadata wiring or inspector behavior.

- [ ] **Step 3: Implement Go runtime-state extraction and merge**

The Go TLS metadata path should:

- key sessions by `(pid, conn_ptr)`
- resolve negotiated TLS version
- resolve cipher suite
- resolve ALPN where practical
- resolve certificates where practical
- map client/server handshake probes to role
- mark `--capture` as requested but not implemented for Go sessions

- [ ] **Step 4: Run the focused tests again and verify they pass**

Run: `/usr/local/go/bin/go test ./pkg/fcktls -run 'TestDaemon.*GoTLSMetadata' -v`

Expected: `PASS`

- [ ] **Step 5: Run package-level regression tests**

Run: `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go test ./pkg/fcktls`

Expected: `ok   github.com/moolen/FCKTLS/pkg/fcktls`

- [ ] **Step 6: Commit the metadata slice**

```bash
git add pkg/fcktls/go_tls_inspector_linux.go pkg/fcktls/go_tls_inspector_linux_test.go pkg/fcktls/daemon.go pkg/fcktls/types.go pkg/fcktls/session_store.go pkg/fcktls/render.go pkg/fcktls/artifacts.go pkg/fcktls/daemon_test.go
git commit -m "feat: add go tls metadata integration"
```

### Task 5: Add Root-Only Integration Coverage And Verify The Runtime

**Files:**
- Modify: `pkg/fcktls/daemon_integration_test.go`
- Modify: `pkg/fcktls/daemon_integration_helpers_test.go`
- Modify: `pkg/ebpf/go_tls_uprobe_bpfeb.go`
- Modify: `pkg/ebpf/go_tls_uprobe_bpfeb.o`
- Modify: `pkg/ebpf/go_tls_uprobe_bpfel.go`
- Modify: `pkg/ebpf/go_tls_uprobe_bpfel.o`

- [ ] **Step 1: Write a failing root-only Go TLS integration test**

The test should:

- build or run a small Go `crypto/tls` client fixture
- start `fcktls` targeting that basename
- verify stop-on-exec attach succeeds
- verify `summary.json` is written
- assert negotiated Go TLS metadata is present

- [ ] **Step 2: Run the integration test to verify the red state**

Run: `sudo -E env PATH=/usr/local/go/bin:/usr/bin:/bin FCKTLS_E2E=1 GOFLAGS= /usr/local/go/bin/go test ./pkg/fcktls -run TestE2EGoTLSMetadata -count=1 -v`

Expected: `FAIL` before the full Go slice is complete.

- [ ] **Step 3: Generate the new BPF objects**

Run: `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go generate ./pkg/ebpf`

Expected: generated `pkg/ebpf/go_tls_uprobe_bpf*.go` and `pkg/ebpf/go_tls_uprobe_bpf*.o` files are updated without errors.

- [ ] **Step 4: Make the integration test pass against a real Go TLS client**

Expected assertions:

- process basename match works
- stop-on-exec attach succeeds
- `summary.json` exists
- metadata shows Go TLS session details

- [ ] **Step 5: Run the full verification suite**

Run: `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go test ./...`

Expected: all unit tests pass

Run: `sudo -E env PATH=/usr/local/go/bin:/usr/bin:/bin FCKTLS_E2E=1 GOFLAGS= /usr/local/go/bin/go test ./pkg/fcktls -run 'TestE2E(TLS12ClientRandomExport|TLS13TrafficSecretExport|GnuTLSCLIPlaintextCapture|GoTLSMetadata)' -count=1 -v`

Expected: all root-only integration tests pass

Run: `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go build ./cmd/fcktls`

Expected: successful build with no output

- [ ] **Step 6: Commit and push the Go TLS slice**

```bash
git add pkg/fcktls/daemon_integration_test.go pkg/fcktls/daemon_integration_helpers_test.go pkg/ebpf/go_tls_uprobe_bpfeb.go pkg/ebpf/go_tls_uprobe_bpfeb.o pkg/ebpf/go_tls_uprobe_bpfel.go pkg/ebpf/go_tls_uprobe_bpfel.o
git commit -m "feat: add go tls runtime support"
git push origin master
```
