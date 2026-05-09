# FCKTLS OpenSSL Curl PoC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a privileged Linux-host Go daemon that matches `curl` by basename, pre-attaches OpenSSL uprobes, emits TLS session metadata and best-effort key status by default, and optionally captures plaintext HTTP via `SSL_read` / `SSL_write`.

**Architecture:** Keep the first slice narrow. Reuse the `../cmon` process-event and OpenSSL uprobe patterns, add OpenSSL application-data probes, correlate everything in a local session store, and render plus persist per-session artifacts under `~/.cache/fcktls`. Treat key export as best-effort and explicit in session state.

**Tech Stack:** Go 1.24, `cilium/ebpf`, Linux uprobes and tracepoints, `bpf2go`, OpenSSL shared-library hooks, standard-library HTTP parsing, Go tests.

---

### Task 1: Scaffold The Module And Core App Contracts

**Files:**
- Create: `go.mod`
- Create: `go.sum`
- Create: `tools.go`
- Create: `pkg/fcktls/config.go`
- Create: `pkg/fcktls/types.go`
- Create: `pkg/fcktls/config_test.go`

- [ ] **Step 1: Write failing config and session-contract tests**
- [ ] **Step 2: Run `go test ./pkg/fcktls -run 'Test(NewConfigDefaults|SessionKeyString|TargetMatcher)' -v` and verify it fails**
- [ ] **Step 3: Add the minimal module, config, and shared types**
- [ ] **Step 4: Run the same tests and verify they pass**

### Task 2: Add Process Events And OpenSSL eBPF Loaders

**Files:**
- Create: `pkg/ebpf/generate.go`
- Create: `pkg/ebpf/objects.go`
- Create: `pkg/ebpf/attach.go`
- Create: `pkg/ebpf/process_events.go`
- Create: `pkg/ebpf/openssl.go`
- Create: `pkg/ebpf/openssl_test.go`
- Create: `pkg/ebpf/process_events_test.go`
- Create: `pkg/ebpf/bpf/process_events.c`
- Create: `pkg/ebpf/bpf/openssl_uprobe.c`

- [ ] **Step 1: Write failing loader and event-decoding tests for process events and OpenSSL events**
- [ ] **Step 2: Run `go test ./pkg/ebpf -run 'Test(DecodeProcessEvent|DecodeOpenSSLEvent|DecodeOpenSSLAppDataEvent|CandidateNamedObjectPaths)' -v` and verify it fails**
- [ ] **Step 3: Adapt the `../cmon` process-event and OpenSSL loader code into `pkg/ebpf`, then extend the BPF program with `SSL_read` / `SSL_write` probes and fixed-size plaintext payload capture**
- [ ] **Step 4: Run `go test ./pkg/ebpf -v` and verify it passes**

### Task 3: Implement Process Matching, Session Correlation, HTTP Formatting, And Artifacts

**Files:**
- Create: `pkg/fcktls/process_monitor.go`
- Create: `pkg/fcktls/openssl_runtime.go`
- Create: `pkg/fcktls/session_store.go`
- Create: `pkg/fcktls/httpfmt.go`
- Create: `pkg/fcktls/artifacts.go`
- Create: `pkg/fcktls/render.go`
- Create: `pkg/fcktls/process_monitor_test.go`
- Create: `pkg/fcktls/session_store_test.go`
- Create: `pkg/fcktls/httpfmt_test.go`
- Create: `pkg/fcktls/artifacts_test.go`

- [ ] **Step 1: Write failing tests for basename matching, session lifecycle, HTTP parsing, and artifact layout**
- [ ] **Step 2: Run `go test ./pkg/fcktls -run 'Test(ProcessMatcher|SessionStore|FormatHTTP|ArtifactWriter)' -v` and verify it fails**
- [ ] **Step 3: Implement the process monitor, session store, HTTP formatter, render helpers, and per-session artifact writer**
- [ ] **Step 4: Run `go test ./pkg/fcktls -run 'Test(ProcessMatcher|SessionStore|FormatHTTP|ArtifactWriter)' -v` and verify it passes**

### Task 4: Wire The Daemon, CLI, And End-To-End Flow

**Files:**
- Create: `cmd/fcktls/main.go`
- Create: `pkg/fcktls/daemon.go`
- Create: `pkg/fcktls/daemon_test.go`
- Create: `Makefile`
- Modify: `pkg/fcktls/config.go`
- Modify: `pkg/fcktls/types.go`

- [ ] **Step 1: Write failing daemon tests for matched exec handling, metadata-only mode, and capture mode**
- [ ] **Step 2: Run `go test ./pkg/fcktls -run 'TestDaemon(MatchedExec|MetadataOnly|CaptureMode)' -v` and verify it fails**
- [ ] **Step 3: Implement the daemon loop that combines process events, OpenSSL events, stdout rendering, and artifact flushes; then add the CLI entrypoint and build helpers**
- [ ] **Step 4: Run `go test ./... -v` and verify the implementation passes**

### Task 5: Generate eBPF Objects, Smoke-Test The Binary, And Push

**Files:**
- Modify: `pkg/ebpf/*.go`
- Modify: `pkg/ebpf/bpf/*.c`
- Modify: `Makefile`

- [ ] **Step 1: Run `go generate ./pkg/ebpf` and fix any object-generation issues**
- [ ] **Step 2: Run `go test ./... -v` again and verify it stays green**
- [ ] **Step 3: Run `go build ./cmd/fcktls` and verify the CLI builds**
- [ ] **Step 4: Commit the implementation and push `master` to `origin`**
