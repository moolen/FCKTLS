# FCKTLS Go TLS Plaintext Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add client-side Go `crypto/tls` plaintext capture to `fcktls` so `--capture` records reassembled request and response streams for matched short-lived Go clients.

**Architecture:** Extend the existing Go per-PID stop-on-exec runtime path with `(*tls.Conn).Write` and `(*tls.Conn).Read` uprobes. Emit Go app-data chunks from eBPF, merge them into the shared session store in the daemon, and verify end to end with the existing detached-process Go TLS integration fixture.

**Tech Stack:** Go 1.25, `cilium/ebpf`, Linux uprobes, ring buffers, root-only integration tests, HTTP artifact rendering.

---

### Task 1: Add Go TLS App-Data eBPF Surface

**Files:**
- Modify: `pkg/ebpf/bpf/go_tls_uprobe.c`
- Modify: `pkg/ebpf/go_tls.go`
- Modify: `pkg/ebpf/go_tls_test.go`
- Regenerate: `pkg/ebpf/go_tls_uprobe_bpfeb.go`
- Regenerate: `pkg/ebpf/go_tls_uprobe_bpfeb.o`
- Regenerate: `pkg/ebpf/go_tls_uprobe_bpfel.go`
- Regenerate: `pkg/ebpf/go_tls_uprobe_bpfel.o`

- [ ] **Step 1: Write failing decode and attach-spec coverage for Go app-data events**

Add tests in `pkg/ebpf/go_tls_test.go` for:
- a decoded `GoTLSAppDataEvent` with `PID`, `ConnPtr`, direction, payload length, and payload bytes
- presence of `crypto/tls.(*Conn).Write` and `crypto/tls.(*Conn).Read` attach specs
- `Write` and `Read` marked optional while `ConnectionState` remains required

- [ ] **Step 2: Run the focused `pkg/ebpf` tests and verify they fail**

Run: `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go test ./pkg/ebpf -run 'Test(DecodeGoTLS|GoTLSAttachSpecs)' -count=1 -v`
Expected: `FAIL` with undefined Go app-data types, readers, or missing attach specs.

- [ ] **Step 3: Implement the BPF-side Go app-data event path**

In `pkg/ebpf/bpf/go_tls_uprobe.c` add:
- an app-data event struct with fixed payload buffer
- a ringbuf map for app-data events
- pending per-thread maps for `Read` and `Write`
- entry probes on `crypto/tls.(*Conn).Write` and `crypto/tls.(*Conn).Read`
- return probes that use the actual return value to copy plaintext bytes and emit events

Required behavior:
- `Write` emits client-to-server payload chunks
- `Read` emits server-to-client payload chunks
- zero/negative return values emit nothing
- payloads are truncated to the event cap

- [ ] **Step 4: Implement the Go loader/app-data reader**

In `pkg/ebpf/go_tls.go` add:
- `GoTLSAppDataDirection`
- `GoTLSAppDataEvent`
- a second ring buffer reader for Go app-data
- `ReadGoTLSAppDataEvent()`
- decode helper for the new event type
- attach specs for `(*tls.Conn).Write` and `(*tls.Conn).Read`

Keep the new app-data attach specs optional so metadata-only support still works for binaries that lack them.

- [ ] **Step 5: Regenerate the eBPF bindings and rerun focused tests**

Run:
- `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go generate ./pkg/ebpf`
- `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go test ./pkg/ebpf -run 'Test(DecodeGoTLS|GoTLSAttachSpecs)' -count=1 -v`
Expected: `PASS`

- [ ] **Step 6: Commit the eBPF slice**

```bash
git add pkg/ebpf/bpf/go_tls_uprobe.c pkg/ebpf/go_tls.go pkg/ebpf/go_tls_test.go pkg/ebpf/go_tls_uprobe_bpfeb.go pkg/ebpf/go_tls_uprobe_bpfeb.o pkg/ebpf/go_tls_uprobe_bpfel.go pkg/ebpf/go_tls_uprobe_bpfel.o
git commit -m "feat: add go tls plaintext probes"
```

### Task 2: Wire Go Plaintext Events Into The Daemon

**Files:**
- Modify: `pkg/fcktls/daemon.go`
- Modify: `pkg/fcktls/daemon_test.go`

- [ ] **Step 1: Write failing daemon tests for Go app-data direction and session merge**

Add tests in `pkg/fcktls/daemon_test.go` covering:
- a Go `Write` app-data event becoming a client-to-server chunk
- a Go `Read` app-data event becoming a server-to-client chunk
- metadata and app-data sharing the same `SessionKey{PID, ConnPtr}`
- capture mode producing stream bytes that later render into request/response artifacts

- [ ] **Step 2: Run the focused daemon tests and verify they fail**

Run: `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go test ./pkg/fcktls -run 'Test(Daemon.*GoTLS|GoTLSInspector)' -count=1 -v`
Expected: `FAIL` with missing Go app-data pump/reader handling.

- [ ] **Step 3: Extend the daemon Go reader interface and run loop**

In `pkg/fcktls/daemon.go`:
- extend `goTLSReader` with `ReadGoTLSAppDataEvent() (ebpf.GoTLSAppDataEvent, error)`
- add a Go app-data channel when `CaptureModeCapture` is enabled
- add `pumpGoTLSAppDataEvents(...)`
- handle Go app-data events in the main select loop

- [ ] **Step 4: Append Go plaintext chunks into the shared store**

Add `handleGoTLSAppDataEvent(...)` that:
- ignores unmatched PIDs or zero `ConnPtr`
- maps Go `Write` to `StreamDirectionClientToServer`
- maps Go `Read` to `StreamDirectionServerToClient`
- appends the payload slice into `SessionStore.AppendChunk`

Do not add new rendering or artifact code; reuse the existing runtime-agnostic path.

- [ ] **Step 5: Run focused package tests and verify they pass**

Run: `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go test ./pkg/fcktls -run 'Test(Daemon.*GoTLS|GoTLSInspector)' -count=1 -v`
Expected: `PASS`

- [ ] **Step 6: Commit the daemon slice**

```bash
git add pkg/fcktls/daemon.go pkg/fcktls/daemon_test.go
git commit -m "feat: capture go tls plaintext streams"
```

### Task 3: Add End-To-End Go Plaintext Coverage

**Files:**
- Modify: `pkg/fcktls/daemon_integration_test.go`

- [ ] **Step 1: Extend the existing Go TLS client e2e with capture assertions**

Update the Go client integration test so it runs with `--capture` and asserts:
- `summary.json` still contains Go metadata
- `request.txt` contains the HTTP request line and `Host` header
- `response.txt` contains the HTTP response line and body
- the detached Go client still exits successfully

Keep the existing guards:
- `linux/amd64`
- `FCKTLS_E2E=1`
- root-only

- [ ] **Step 2: Run the focused e2e and verify it passes**

Run: `sudo -E env PATH=/usr/local/go/bin:/usr/bin:/bin FCKTLS_E2E=1 GOFLAGS= /usr/local/go/bin/go test ./pkg/fcktls -run 'TestE2EGoTLSClientStopOnExecAttach' -count=1 -v`
Expected: `PASS`

- [ ] **Step 3: Run full verification**

Run:
- `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go test ./... -count=1`
- `PATH=/usr/local/go/bin:/usr/bin:/bin /usr/local/go/bin/go build ./cmd/fcktls`

Expected:
- all tests pass
- the CLI builds successfully

- [ ] **Step 4: Commit the e2e slice**

```bash
git add pkg/fcktls/daemon_integration_test.go
git commit -m "test: cover go tls plaintext capture"
```
