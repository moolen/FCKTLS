# FCKTLS Go TLS Design

## Goal

Add a third runtime slice to `fcktls` for Go executables using `crypto/tls`, with a first user flow like:

- `fcktls --target my-go-client`
- `my-go-client`

The first Go slice must preserve the same top-level user model as the existing runtimes:

- basename process matching
- metadata and best-effort key export by default
- live stdout rendering
- per-session artifacts under `~/.cache/fcktls`

Unlike OpenSSL and GnuTLS, the Go slice must also introduce a stop-on-exec control path so short-lived Go processes can be instrumented reliably before they enter `crypto/tls`.

## Non-Goals

This slice does not need to:

- support stripped or symbol-less Go binaries
- implement plaintext capture yet
- redesign the existing OpenSSL or GnuTLS paths
- add tc or wire capture
- provide generic stop-on-exec for every runtime

## Recommended Approach

The recommended approach is a Go-specific per-process attach model:

1. match target processes by basename at exec time
2. inspect the binary for required `crypto/tls.(*Conn)` symbols
3. stop the matching process briefly
4. attach Go TLS uprobes to that specific PID and executable
5. resume the process
6. merge Go TLS metadata into the existing session model

This is preferred over attach-after-exec polling because the product requirement is reliable interception of short-lived targets.

## User Experience

### Default mode

`fcktls --target my-go-client` starts the daemon and:

- monitors process exec and exit events
- keeps OpenSSL and GnuTLS shared-library attachments active as before
- inspects matched executables for Go `crypto/tls` support
- temporarily pauses supported Go targets during attach
- prints Go TLS session metadata for matched processes
- writes artifacts under `~/.cache/fcktls`

The live metadata output should include, when available:

- PID and executable path
- source and destination tuple
- role
- SNI
- TLS version
- cipher suite
- ALPN
- certificate summary
- key export status

### Capture mode

This first Go slice does not add plaintext capture yet.

If `--capture` is supplied for a Go target during this slice:

- the process should still be intercepted and metadata should still be emitted
- the session should explicitly record that Go plaintext capture is not implemented yet

The stop-on-exec control path built here is the prerequisite for the next Go slice that will add plaintext capture.

## Attachment Model

Go TLS must use a per-process attachment model rather than the shared-library model used by OpenSSL and GnuTLS.

- attach to the executable, not a shared library
- scope uprobes to the matched PID
- require the expected `crypto/tls.(*Conn)` symbols to be present
- stop the process before attach, then resume it

This is required because Go `crypto/tls` lives inside each executable and short-lived clients would otherwise race the attach flow.

## Required Symbols

For the first Go slice, a target binary is supported only if it exposes:

- `crypto/tls.(*Conn).clientHandshake`
- `crypto/tls.(*Conn).serverHandshake`
- `crypto/tls.(*Conn).ConnectionState`

If any required symbol is missing, `fcktls` must treat the process as unsupported for the Go slice and resume it immediately.

## Components

### `pkg/ebpf/go_tls.go`

Adapts reusable pieces from `../cmon/pkg/ebpf/go_tls.go`:

- event structs
- decode helpers
- per-PID attach logic
- loader lifecycle

### `pkg/ebpf/bpf/go_tls_uprobe.c`

Provides Go TLS BPF programs for:

- `crypto/tls.(*Conn).clientHandshake`
- `crypto/tls.(*Conn).serverHandshake`
- `crypto/tls.(*Conn).ConnectionState`

The first slice only needs metadata-oriented events keyed by process and Go `Conn` pointer.

### `pkg/fcktls/go_binary_inspector.go`

Adapts the Go executable inspection logic from `../cmon` to:

- identify Go executables
- read symbol tables
- verify the required `crypto/tls` symbols are present

### `pkg/fcktls/go_exec_gate.go`

Introduces a small stop-on-exec controller that:

- receives matched exec events
- stops the process
- performs Go attach work
- resumes the process on success or failure

### `pkg/fcktls/daemon.go`

Extends the daemon loop to:

- manage a Go TLS loader
- route matched execs through the Go exec gate
- consume Go TLS events
- merge Go metadata into the shared session store

### Shared packages

The following packages should remain runtime-agnostic and be reused:

- `pkg/fcktls/session_store.go`
- `pkg/fcktls/render.go`
- `pkg/fcktls/artifacts.go`

## Data Flow

1. `fcktls` starts and attaches process exec/exit monitoring.
2. OpenSSL and GnuTLS attachments are initialized as they are today.
3. A new process execs.
4. If the resolved basename matches the configured target, `fcktls` inspects the executable for Go `crypto/tls` support.
5. If the binary is a supported Go target, `fcktls` stops the process.
6. Go TLS uprobes are attached to that PID and executable.
7. The process is resumed.
8. Go TLS probes emit events for:
   - client handshake
   - server handshake
   - connection state
9. The daemon reads Go runtime state from the traced process and extracts negotiated metadata.
10. The session store merges the resulting metadata under `(pid, conn_ptr)`.
11. The renderer prints the session summary and artifacts are written under the normal cache layout.
12. On process exit, sessions are finalized as usual.

## Session Model Expectations

The existing session model is flexible enough for Go TLS and should be reused.

The first Go slice should populate, when available:

- session identifier
- PID and executable path
- source and destination tuple
- role
- SNI
- TLS version
- cipher suite
- ALPN
- certificates
- key status

Fields unavailable from a given Go version or binary must remain absent rather than guessed.

## Stop-On-Exec Semantics

The stop-on-exec path should be narrowly scoped:

- only for matched basenames
- only for supported Go binaries
- only long enough to complete inspection and uprobe attach

The daemon must always resume the process, including attach failure paths.

The stop window should be kept minimal so developer workflows are not noticeably impacted beyond the interception point.

## Key Export Semantics

Key export remains best-effort for the first Go slice.

Per matched Go session:

- attempt extraction only when a safe runtime path exists
- explicitly record success or failure
- persist captured key-log material to `keys.log` when available
- never fail the overall session solely because key export is unavailable

Expected states remain:

- `available`
- `unavailable`
- `partial`
- `error`

## Capture Semantics

The first Go slice does not implement plaintext capture.

If a Go session is observed while `--capture` is enabled:

- metadata should still be emitted normally
- the summary should reflect that capture mode was requested
- the session should explicitly note that Go plaintext capture is not implemented yet

This makes the limitation visible while preserving the future-compatible UX.

## Errors

- If a matched process is not a Go binary, continue normal runtime handling and do not treat it as a Go error.
- If a matched process is a Go binary but lacks the required `crypto/tls` symbols, resume it and treat it as unsupported for the Go slice.
- If stop-on-exec or attach fails, resume the process and record a clear failure reason.
- If Go probe events arrive but remote state extraction fails, emit partial metadata when possible.
- If the process exits before attach completes, treat that as a miss rather than a daemon-fatal condition.

## Testing

Add tests in four layers.

### `pkg/ebpf`

- decode tests for Go TLS event structs
- attach-spec tests for required Go symbols

### Binary inspection

- unit tests for Go binary inspection and required-symbol gating

### `pkg/fcktls`

- daemon tests for stop-on-exec attach gating
- daemon tests for unsupported Go binaries resuming cleanly
- daemon tests for Go TLS metadata merge

### Root-only integration

Add at least one root-only integration test using a small local Go `crypto/tls` client fixture and verify:

- basename match works
- stop-on-exec attach succeeds
- metadata is emitted
- artifacts are created

## Reuse From `../cmon`

This slice should intentionally reuse `../cmon` where practical:

- `pkg/ebpf/go_tls.go`
- `pkg/ebpf/bpf/go_tls_uprobe.c`
- Go executable inspection logic from `pkg/agent/uprobe_discovery.go`
- Go runtime-state reading logic from `pkg/agent/uprobe_collector.go`

FCKTLS should only adapt what is needed to fit the local daemon, session, rendering, and artifact model.

## Deferred Work

After the first Go slice:

1. add Go plaintext capture using the stop-on-exec foundation built here
2. strengthen key export where practical
3. decide whether generic stop-on-exec should become a shared control plane across runtimes
