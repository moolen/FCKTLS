# FCKTLS Go TLS Plaintext Capture Design

## Goal

Add the first Go `crypto/tls` plaintext capture slice to `fcktls` for client-side Go binaries. The tool should keep the existing stop-on-exec attach flow, and when started with `--capture`, it should capture Go TLS plaintext application data, reassemble directional streams, pretty-print HTTP when possible, and persist the same artifacts already produced for OpenSSL and GnuTLS.

This slice is intentionally scoped to:
- client-side Go `crypto/tls`
- plaintext at the `tls.Conn` application boundary
- stream reassembly by direction, not original application message boundaries

This slice explicitly does not include:
- server-side Go plaintext capture guarantees
- Go key export
- exact message-boundary reconstruction
- wire-level decryption fallback

## Context

`fcktls` already supports:
- OpenSSL metadata, key export, and plaintext capture
- GnuTLS metadata and plaintext capture
- Go `crypto/tls` metadata with stop-on-exec per-PID attach

The missing piece is Go plaintext. Unlike OpenSSL and GnuTLS, Go TLS is embedded in the target binary, so capture must remain per-process and version-sensitive. That is acceptable for this tool: OpenSSL and similar paths already depend on version-sensitive hooks, and the immediate goal is a working end-to-end plaintext debugger.

## Approaches

### 1. Hook `(*tls.Conn).Write` and `(*tls.Conn).Read`

Attach client-side plaintext probes directly to `crypto/tls.(*Conn).Write` and `crypto/tls.(*Conn).Read`, emit chunks keyed by `(pid, conn)`, and reuse the existing session store and HTTP rendering pipeline.

Pros:
- best fit for the current `fcktls` UX
- captures plaintext close to the TLS application boundary
- reuses existing session, rendering, and artifact code
- compatible with the current stop-on-exec Go attach model

Cons:
- depends on Go internal symbol stability and calling convention details
- produces chunked streams rather than original app message boundaries

### 2. Hook deeper record-layer internals

Capture below `Read` and `Write`, closer to record processing.

Pros:
- potentially more precise TLS-layer semantics

Cons:
- more fragile than the public-ish method boundary
- more work for less immediate user value

### 3. Defer Go plaintext and rely on future wire+keys

Keep Go metadata only for now.

Pros:
- lower short-term implementation risk

Cons:
- does not meet the immediate product goal

## Recommendation

Implement approach 1.

Capture per-call plaintext chunks from `(*tls.Conn).Write` and `(*tls.Conn).Read`, then reconstruct the “whole picture” in userspace by concatenating chunks into directional byte streams. This matches the current OpenSSL and GnuTLS output model and gives the desired end-to-end debugging experience quickly.

## Architecture

The existing Go runtime path remains the control plane:
- basename process match
- stop matched process on exec
- inspect binary for required Go TLS symbols
- attach per-PID uprobes
- resume process

This design adds a Go plaintext data plane on top of that:
- metadata probes remain:
  - `crypto/tls.(*Conn).clientHandshake`
  - `crypto/tls.(*Conn).serverHandshake`
  - `crypto/tls.(*Conn).ConnectionState`
- app-data probes are added:
  - `crypto/tls.(*Conn).Write`
  - `crypto/tls.(*Conn).Read`

The daemon consumes both event classes:
- metadata events continue to populate the Go session summary
- app-data events are appended into the shared plaintext stream store
- final rendering and artifacts remain runtime-agnostic

## Components

### `pkg/ebpf/bpf/go_tls_uprobe.c`

Extend the Go TLS BPF program with app-data probes:
- `uprobe` on `(*tls.Conn).Write`
- `uretprobe` on `(*tls.Conn).Write`
- `uprobe` on `(*tls.Conn).Read`
- `uretprobe` on `(*tls.Conn).Read`

Use per-thread pending maps to carry state from entry to return:
- `conn` pointer
- user buffer pointer
- requested buffer length
- direction

On return:
- read the actual return value
- if `n > 0`, copy up to the per-event payload cap from user memory
- emit an app-data event with `(timestamp, pid, tid, conn, direction, payload_len, payload)`

### `pkg/ebpf/go_tls.go`

Extend the Go loader with:
- an app-data ring buffer map/object
- `ReadGoTLSAppDataEvent()`
- app-data event decode helpers
- app-data attach specs for `Read` and `Write`

The metadata symbols remain required as they are today, while the new plaintext symbols are best-effort for supported client binaries.

### `pkg/fcktls/daemon.go`

Add a Go app-data pump when `CaptureModeCapture` is enabled.

Behavior:
- metadata-only mode: unchanged
- capture mode: read Go app-data events and convert them into `PlaintextChunk`s
- `Write` maps to client-to-server
- `Read` maps to server-to-client
- append chunks using the existing `SessionStore.AppendChunk`

No new user-facing flags are required.

### Shared packages

No structural changes are required in:
- `pkg/fcktls/session_store.go`
- `pkg/fcktls/render.go`
- `pkg/fcktls/artifacts.go`

These already support concatenated directional streams and HTTP rendering.

## Data Flow

1. `fcktls --target <go-client> --capture` starts.
2. A matched Go client execs.
3. `fcktls` stops the process, inspects the binary, attaches metadata and plaintext Go probes for the PID, and resumes it.
4. During TLS handshake and steady-state traffic:
   - metadata probes emit handshake and `ConnectionState` events
   - `Write` emits client-to-server plaintext chunks
   - `Read` emits server-to-client plaintext chunks
5. The daemon correlates all Go events on `SessionKey{PID, ConnPtr}`.
6. The session store concatenates plaintext chunks by direction.
7. On exit, finalization writes:
   - `summary.json`
   - `request.txt`
   - `response.txt`
8. Stdout prints the metadata summary and formatted HTTP when parseable.

## Stream Semantics

This slice defines “whole picture” as reassembled directional byte streams.

That means:
- data may arrive split across multiple `Read` or `Write` calls
- userspace concatenates those chunks in arrival order per direction
- HTTP formatting runs on the reassembled directional stream
- exact original application message boundaries are not preserved yet

This is acceptable for the current goal and can be refined later with boundary-aware framing.

## Direction Mapping

For the client-side-first slice:
- `(*tls.Conn).Write` means client-to-server plaintext
- `(*tls.Conn).Read` means server-to-client plaintext

Server-side Go plaintext support is intentionally deferred. The initial implementation does not promise correct directionality or coverage for Go TLS servers.

## Error Handling

- If `Read` or `Write` symbols are missing in a matched Go binary, metadata capture may still proceed; plaintext capture is treated as unavailable for that process.
- If a probe return value is zero or negative, emit no plaintext chunk.
- If a payload exceeds the per-event BPF cap, truncate that event and rely on subsequent calls to continue the stream.
- If plaintext arrives before metadata, still append it by `(pid, conn)` and allow later metadata events to enrich the same session.
- If HTTP parsing fails, preserve the raw reassembled stream in artifacts and use the existing fallback text rendering.

## Testing

### Unit tests

`pkg/ebpf/go_tls_test.go`
- decode tests for Go app-data events
- attach-spec tests for `Read` and `Write`

`pkg/fcktls/daemon_test.go`
- verify Go app-data events map to the correct direction
- verify app-data and metadata merge on the same session key

### Root-only integration test

Extend the current Go TLS client e2e to run with capture enabled and assert:
- Go metadata is still emitted
- `request.txt` contains the HTTP request
- `response.txt` contains the HTTP response and body
- the client still completes successfully under stop-on-exec attach

## Scope Boundaries

Included now:
- client-side Go plaintext capture
- stream reassembly by direction
- HTTP rendering and artifacts through the shared pipeline

Deferred:
- server-side Go plaintext capture
- app message boundary recovery
- Go key export
- packet capture fallback for Go plaintext

## Success Criteria

A short-lived Go client binary matched by basename should work end to end with:
- `fcktls --target <basename>`
  - emits Go TLS metadata as today
- `fcktls --target <basename> --capture`
  - emits the same metadata
  - captures Go TLS plaintext request and response streams
  - writes `request.txt` and `response.txt`
  - pretty-prints HTTP when possible
