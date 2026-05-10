# FCKTLS GnuTLS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a GnuTLS runtime slice to `fcktls` that matches basename-targeted clients like `wget`, emits GnuTLS metadata and best-effort keys by default, and optionally captures plaintext application data with `--capture`.

**Architecture:** Reuse the existing OpenSSL daemon/session/render/artifact pipeline and adapt `../cmon`’s GnuTLS shared-library uprobe model into `pkg/ebpf` plus daemon normalization logic. Keep the user-facing contract unchanged: pre-attach shared-library probes, filter by matched PID in userspace, and persist per-session outputs under the existing cache layout.

**Tech Stack:** Go 1.24, `cilium/ebpf`, Linux uprobes and ring buffers, `bpf2go`, GnuTLS shared-library hooks, standard-library HTTP parsing, root-only Go integration tests.

---

### Task 1: Add GnuTLS eBPF Loader, Event Types, And Attach Surface

**Files:**
- Create: `pkg/ebpf/gnutls.go`
- Create: `pkg/ebpf/gnutls_test.go`
- Create: `pkg/ebpf/bpf/gnutls_uprobe.c`
- Modify: `pkg/ebpf/generate.go`
- Modify: `pkg/ebpf/attach.go`
- Modify: `pkg/ebpf/process_events_test.go`

- [ ] **Step 1: Write the failing decode and attach-spec tests in `pkg/ebpf/gnutls_test.go`**

```go
func TestDecodeGnuTLSEvent(t *testing.T) {
	raw := make([]byte, gnuTLSEventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 11)
	binary.LittleEndian.PutUint32(raw[8:12], 4242)
	binary.LittleEndian.PutUint32(raw[12:16], 4343)
	binary.LittleEndian.PutUint64(raw[16:24], 0xfeedbeef)
	raw[36] = byte(GnuTLSProbeKindHandshake)
	raw[37] = byte(GnuTLSEventTypeHandshake)
	copy(raw[40:104], []byte("NORMAL:-VERS-TLS1.3"))

	event, err := decodeGnuTLSEvent(raw)
	if err != nil {
		t.Fatalf("decodeGnuTLSEvent() error = %v", err)
	}
	if got, want := event.EventType, GnuTLSEventTypeHandshake; got != want {
		t.Fatalf("EventType = %d, want %d", got, want)
	}
	if got, want := event.StringPayload(), "NORMAL:-VERS-TLS1.3"; got != want {
		t.Fatalf("StringPayload() = %q, want %q", got, want)
	}
}

func TestGnuTLSUprobeAttachSpecs(t *testing.T) {
	specs := gnuTLSUprobeAttachSpecs(gnuTLSObjects{})
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		names = append(names, spec.symbol)
	}
	for _, want := range []string{
		"gnutls_handshake",
		"gnutls_transport_set_int2",
		"gnutls_server_name_set",
		"gnutls_priority_set_direct",
	} {
		if !slices.Contains(names, want) {
			t.Fatalf("attach specs missing %q", want)
		}
	}
}
```

- [ ] **Step 2: Run the focused `pkg/ebpf` tests and verify they fail for the missing GnuTLS surface**

Run: `/usr/local/go/bin/go test ./pkg/ebpf -run 'Test(DecodeGnuTLSEvent|GnuTLSUprobeAttachSpecs)' -v`

Expected: `FAIL` with undefined `GnuTLSEvent`, `decodeGnuTLSEvent`, `gnuTLSUprobeAttachSpecs`, or missing generated-object references.

- [ ] **Step 3: Implement the minimal GnuTLS event and loader surface in `pkg/ebpf/gnutls.go` and `pkg/ebpf/bpf/gnutls_uprobe.c`**

```go
type GnuTLSProbeKind uint8

const (
	GnuTLSProbeKindUnknown GnuTLSProbeKind = iota
	GnuTLSProbeKindHandshake
	GnuTLSProbeKindTransportSetInt2
	GnuTLSProbeKindServerNameSet
	GnuTLSProbeKindPrioritySetDirect
	GnuTLSProbeKindSessionIsResumed
	GnuTLSProbeKindVerifyStatus
	GnuTLSProbeKindGroupGet
	GnuTLSProbeKindRecordRecv
	GnuTLSProbeKindRecordSend
)

type GnuTLSEventType uint8

const (
	GnuTLSEventTypeUnknown GnuTLSEventType = iota
	GnuTLSEventTypeHandshake
	GnuTLSEventTypeSetFD
	GnuTLSEventTypeSetSNI
	GnuTLSEventTypeSetPriority
	GnuTLSEventTypeSessionResumed
	GnuTLSEventTypeVerifyStatus
	GnuTLSEventTypeNegotiatedGroup
)

type GnuTLSEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	SessionPtr  uint64
	DataPtr     uint64
	Value       int32
	ProbeKind   GnuTLSProbeKind
	EventType   GnuTLSEventType
	_           [2]byte
	Bytes       [64]byte
}

func (e GnuTLSEvent) StringPayload() string {
	end := bytes.IndexByte(e.Bytes[:], 0)
	if end == -1 {
		end = len(e.Bytes)
	}
	return string(e.Bytes[:end])
}
```

```c
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

SEC("uprobe/gnutls_handshake")
int gnutls_handshake_enter(struct pt_regs *ctx) {
	__u64 session_ptr = PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&gnutls_pending, &bpf_get_current_pid_tgid(), &session_ptr, BPF_ANY);
	return 0;
}

SEC("uretprobe/gnutls_handshake")
int gnutls_handshake_return(struct pt_regs *ctx) {
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
int gnutls_transport_set_int2_enter(struct pt_regs *ctx) {
	struct gnutls_fd_pending value = {};
	value.session_ptr = PT_REGS_PARM1(ctx);
	value.fd = (__s32)PT_REGS_PARM2(ctx);
	bpf_map_update_elem(&gnutls_fd_pending, &bpf_get_current_pid_tgid(), &value, BPF_ANY);
	return 0;
}

SEC("uprobe/gnutls_server_name_set")
int gnutls_server_name_set_enter(struct pt_regs *ctx) {
	struct gnutls_sni_pending value = {};
	value.session_ptr = PT_REGS_PARM1(ctx);
	bpf_probe_read_user_str(value.name, sizeof(value.name), (void *)PT_REGS_PARM3(ctx));
	bpf_map_update_elem(&gnutls_sni_pending, &bpf_get_current_pid_tgid(), &value, BPF_ANY);
	return 0;
}
```

- [ ] **Step 4: Add the generate directive and generated-object integration**

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86" gnutls_uprobe ./bpf/gnutls_uprobe.c -- -I./bpf
```

- [ ] **Step 5: Run the focused `pkg/ebpf` tests again and verify they pass**

Run: `/usr/local/go/bin/go test ./pkg/ebpf -run 'Test(DecodeGnuTLSEvent|GnuTLSUprobeAttachSpecs)' -v`

Expected: `PASS`

- [ ] **Step 6: Commit the loader/BPF slice**

```bash
git add pkg/ebpf/gnutls.go pkg/ebpf/gnutls_test.go pkg/ebpf/bpf/gnutls_uprobe.c pkg/ebpf/generate.go pkg/ebpf/attach.go
git commit -m "feat: add gnutls ebpf loader"
```

### Task 2: Integrate GnuTLS Runtime Events Into The Daemon And Shared Session Model

**Files:**
- Modify: `pkg/fcktls/daemon.go`
- Modify: `pkg/fcktls/daemon_test.go`
- Modify: `pkg/fcktls/types.go`
- Modify: `pkg/fcktls/session_store.go`
- Modify: `pkg/fcktls/render.go`
- Modify: `pkg/fcktls/artifacts.go`

- [ ] **Step 1: Write failing daemon tests for GnuTLS metadata merge and optional capture**

```go
func TestDaemonMergesGnuTLSMetadataEvent(t *testing.T) {
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	cfg, _ := NewConfig("wget", false, t.TempDir())

	d := &Daemon{
		Config:  cfg,
		Monitor: NewProcessMonitor("wget", staticExeResolver{paths: map[int]string{707: "/usr/bin/wget"}}),
		Now:     func() time.Time { return now },
		Stdout:  io.Discard,
		Store:   NewSessionStore(),
	}

	tracked := map[int]ProcessMatch{707: {PID: 707, ExePath: "/usr/bin/wget", Basename: "wget"}}
	seen := map[int]bool{707: false}
	fds := make(map[SessionKey]int)

	d.handleGnuTLSEvent(ebpf.GnuTLSEvent{
		PID:        707,
		TimestampNS: uint64(now.UnixNano()),
		SessionPtr: 0x7,
		EventType:  ebpf.GnuTLSEventTypeSetSNI,
		Bytes:      toSNIBytes("example.com"),
	}, tracked, seen, fds)

	snapshot, ok := d.Store.Finalize(SessionKey{PID: 707, SSLPointer: 0x7}, now.Add(time.Millisecond))
	if !ok {
		t.Fatal("Finalize() ok = false, want true")
	}
	if got, want := snapshot.Metadata.SNI, "example.com"; got != want {
		t.Fatalf("SNI = %q, want %q", got, want)
	}
}

func TestDaemonCapturesGnuTLSPlaintext(t *testing.T) {
	cfg, _ := NewConfig("wget", true, t.TempDir())
	d := &Daemon{Config: cfg, Store: NewSessionStore(), Stdout: io.Discard}

	tracked := map[int]ProcessMatch{808: {PID: 808, ExePath: "/usr/bin/wget", Basename: "wget"}}
	d.handleGnuTLSAppDataEvent(newGnuTLSAppDataEvent(808, 0x8, ebpf.GnuTLSAppDataDirectionSend, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")), tracked)

	snapshot, ok := d.Store.Finalize(SessionKey{PID: 808, SSLPointer: 0x8}, time.Now())
	if !ok {
		t.Fatal("Finalize() ok = false, want true")
	}
	if !strings.Contains(string(snapshot.Streams.ClientToServer), "GET / HTTP/1.1") {
		t.Fatalf("client stream = %q, want HTTP request", snapshot.Streams.ClientToServer)
	}
}
```

- [ ] **Step 2: Run the focused daemon tests and verify they fail before implementation**

Run: `/usr/local/go/bin/go test ./pkg/fcktls -run 'TestDaemon(MergesGnuTLSMetadataEvent|CapturesGnuTLSPlaintext)' -v`

Expected: `FAIL` with undefined `handleGnuTLSEvent`, `handleGnuTLSAppDataEvent`, `GnuTLSEvent`, or missing runtime wiring.

- [ ] **Step 3: Extend the daemon to read GnuTLS events and normalize them into existing session updates**

```go
type gnuTLSReader interface {
	AttachLibraryPath(string) error
	ReadGnuTLSEvent() (ebpf.GnuTLSEvent, error)
	ReadGnuTLSAppDataEvent() (ebpf.GnuTLSAppDataEvent, error)
	Close() error
}

func (d *Daemon) handleGnuTLSEvent(event ebpf.GnuTLSEvent, tracked map[int]ProcessMatch, seenGnuTLS map[int]bool, fdBySession map[SessionKey]int) {
	match, ok := tracked[int(event.PID)]
	if !ok || event.SessionPtr == 0 {
		return
	}

	key := SessionKey{PID: int(event.PID), SSLPointer: event.SessionPtr}
	update := SessionMetadataUpdate{
		Key:         key,
		ObservedAt:  time.Unix(0, int64(event.TimestampNS)),
		PID:         int(event.PID),
		ExePath:     match.ExePath,
		LibraryPath: firstAttachedLibraryPath(d.GnuTLS),
		CaptureMode: d.Config.CaptureMode,
	}

	switch event.EventType {
	case ebpf.GnuTLSEventTypeSetSNI:
		update.SNI = event.StringPayload()
	case ebpf.GnuTLSEventTypeSetPriority:
		update.Groups = event.StringPayload()
	case ebpf.GnuTLSEventTypeSetFD:
		fd := int(event.Value)
		update.SocketFD = &fd
	}

	d.Store.MergeMetadata(update)
}
```

- [ ] **Step 4: Reuse the existing HTTP formatter and artifact writer for GnuTLS capture**

```go
func (d *Daemon) handleGnuTLSAppDataEvent(event ebpf.GnuTLSAppDataEvent, tracked map[int]ProcessMatch) {
	if _, ok := tracked[int(event.PID)]; !ok || event.SessionPtr == 0 {
		return
	}
	direction := StreamDirectionClientToServer
	if event.Direction == ebpf.GnuTLSAppDataDirectionRecv {
		direction = StreamDirectionServerToClient
	}
	d.Store.AppendChunk(PlaintextChunk{
		Key:        SessionKey{PID: int(event.PID), SSLPointer: event.SessionPtr},
		Direction:  direction,
		ObservedAt: time.Unix(0, int64(event.TimestampNS)),
		Data:       append([]byte(nil), event.Payload[:event.PayloadLength]...),
	})
}
```

- [ ] **Step 5: Run the focused daemon tests and verify they pass**

Run: `/usr/local/go/bin/go test ./pkg/fcktls -run 'TestDaemon(MergesGnuTLSMetadataEvent|CapturesGnuTLSPlaintext)' -v`

Expected: `PASS`

- [ ] **Step 6: Run the package-level regression tests and verify OpenSSL remains green**

Run: `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go test ./pkg/fcktls`

Expected: `ok   github.com/moolen/FCKTLS/pkg/fcktls`

- [ ] **Step 7: Commit the daemon/runtime integration**

```bash
git add pkg/fcktls/daemon.go pkg/fcktls/daemon_test.go pkg/fcktls/types.go pkg/fcktls/session_store.go pkg/fcktls/render.go pkg/fcktls/artifacts.go
git commit -m "feat: add gnutls daemon integration"
```

### Task 3: Add Integration Coverage, Generate Objects, And Verify The Runtime

**Files:**
- Modify: `pkg/fcktls/daemon_integration_test.go`
- Modify: `pkg/fcktls/daemon_integration_helpers_test.go`
- Modify: `pkg/ebpf/gnutls_uprobe_bpfeb.go`
- Modify: `pkg/ebpf/gnutls_uprobe_bpfeb.o`
- Modify: `pkg/ebpf/gnutls_uprobe_bpfel.go`
- Modify: `pkg/ebpf/gnutls_uprobe_bpfel.o`

- [ ] **Step 1: Write a failing root-only GnuTLS integration test in `pkg/fcktls/daemon_integration_test.go`**

```go
func TestE2EGnuTLSWgetMetadata(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("linux/amd64 only")
	}
	if os.Getenv("FCKTLS_E2E") == "" {
		t.Skip("set FCKTLS_E2E=1 to run e2e test")
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for eBPF integration")
	}
	if _, err := exec.LookPath("wget"); err != nil {
		t.Skip("wget not installed")
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "gnutls-ok\n")
	}))
	defer server.Close()

	cacheRoot := t.TempDir()
	cfg, _ := NewConfig("wget", false, cacheRoot)
	daemon, _ := NewDaemon(cfg)
	daemon.Stdout = io.Discard
	ready := make(chan struct{})
	daemon.OnReady = func() { close(ready) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- daemon.Run(ctx) }()

	select {
	case <-ready:
	case err := <-runErrCh:
		t.Fatalf("daemon exited before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for daemon readiness")
	}

	stdoutPath := filepath.Join(cacheRoot, "wget.out")
	stderrPath := filepath.Join(cacheRoot, "wget.err")
	statusPath := filepath.Join(cacheRoot, "wget.status")
	pid, err := launchDetachedCommand(stdoutPath, stderrPath, statusPath, "wget", "-qO-", "--no-check-certificate", server.URL)
	if err != nil {
		t.Fatalf("launchDetachedCommand() error = %v", err)
	}
	defer terminateDetachedProcessGroup(pid)

	result, err := waitForDetachedCommand(statusPath, 15*time.Second)
	if err != nil {
		t.Fatalf("waitForDetachedCommand() error = %v", err)
	}
	if got, want := result.ExitCode, 0; got != want {
		t.Fatalf("wget exit code = %d, want %d", got, want)
	}

	summaryPath, _, err := waitForSessionFiles(cacheRoot, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	rawSummary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("ReadFile(summary.json) error = %v", err)
	}
	if !bytes.Contains(rawSummary, []byte(`"exe_path":"/usr/bin/wget"`)) {
		t.Fatalf("summary.json = %s, want wget session", rawSummary)
	}
}
```

- [ ] **Step 2: Run the integration test to verify the red state**

Run: `sudo -E env PATH=/usr/local/go/bin:/usr/bin:/bin FCKTLS_E2E=1 GOFLAGS= /usr/local/go/bin/go test ./pkg/fcktls -run TestE2EGnuTLSWgetMetadata -count=1 -v`

Expected: `FAIL` because GnuTLS readers are not yet fully wired, symbols are missing, or no summary is produced.

- [ ] **Step 3: Generate the new BPF objects and fix any codegen issues**

Run: `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go generate ./pkg/ebpf`

Expected: generated `pkg/ebpf/gnutls_uprobe_bpf*.go` and `pkg/ebpf/gnutls_uprobe_bpf*.o` files are updated without errors.

- [ ] **Step 4: Make the integration test pass against a real GnuTLS-linked client**

```go
result, err := waitForDetachedCommand(statusPath, 15*time.Second)
if err != nil {
	t.Fatalf("waitForDetachedCommand() error = %v", err)
}
if got, want := result.ExitCode, 0; got != want {
	t.Fatalf("wget exit code = %d, want %d", got, want)
}

summaryPath, _, err := waitForSessionFiles(cacheRoot, 10*time.Second)
if err != nil {
	t.Fatal(err)
}

rawSummary, err := os.ReadFile(summaryPath)
if err != nil {
	t.Fatalf("ReadFile(summary.json) error = %v", err)
}
if !bytes.Contains(rawSummary, []byte(`"exe_path":"/usr/bin/wget"`)) {
	t.Fatalf("summary.json = %s, want wget session", rawSummary)
}
```

- [ ] **Step 5: Run the full verification suite**

Run: `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go test ./...`

Expected: all unit tests pass

Run: `sudo -E env PATH=/usr/local/go/bin:/usr/bin:/bin FCKTLS_E2E=1 GOFLAGS= /usr/local/go/bin/go test ./pkg/fcktls -run 'TestE2E(TLS12ClientRandomExport|TLS13TrafficSecretExport|GnuTLSWgetMetadata)' -count=1 -v`

Expected: all three root-only integration tests pass

Run: `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go build ./cmd/fcktls`

Expected: successful build with no output

- [ ] **Step 6: Commit and push the GnuTLS slice**

```bash
git add pkg/fcktls/daemon_integration_test.go pkg/fcktls/daemon_integration_helpers_test.go pkg/ebpf/gnutls_uprobe_bpfeb.go pkg/ebpf/gnutls_uprobe_bpfeb.o pkg/ebpf/gnutls_uprobe_bpfel.go pkg/ebpf/gnutls_uprobe_bpfel.o
git commit -m "feat: add gnutls runtime support"
git push origin master
```
