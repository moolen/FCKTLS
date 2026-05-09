# FCKTLS OpenSSL Curl PoC Design

## Goal

Build a privileged Linux-host debugging daemon named `fcktls` that helps developers understand TLS activity for short-lived local processes. The first vertical slice targets `curl` linked against OpenSSL.

The PoC must support:

- running as `fcktls --target curl`
- matching processes by executable basename
- reporting TLS metadata and best-effort key export by default
- optionally capturing plaintext application data with `--capture`
- printing live output to stdout
- writing per-session artifacts under `~/.cache/fcktls`

The long-term product direction remains hybrid: process/runtime hooks for attribution and metadata, plus either plaintext runtime hooks or wire capture plus userspace decryption depending on runtime feasibility.

## Non-Goals

The PoC does not need to:

- support GnuTLS, Go `crypto/tls`, Java, or NSS in the first implementation
- implement generic stop-on-exec across all runtimes
- decrypt network traffic from wire data alone
- provide a stable remote API, UI, or multi-user service model
- guarantee Wireshark-compatible key export for every session

## User Experience

### Default mode

`fcktls --target curl` starts a privileged local daemon that:

- monitors process exec and exit events
- pre-attaches OpenSSL uprobes to discovered `libssl.so*` libraries
- tracks processes whose resolved executable basename is `curl`
- prints TLS session metadata for matched processes
- attempts to export key material for later Wireshark use
- writes session artifacts under `~/.cache/fcktls`

The default live output includes:

- PID and executable path
- source and destination tuple
- SNI
- TLS version
- selected cipher suite
- ALPN
- certificate summary
- key export status and, when available, key log lines or their artifact location

### Capture mode

`fcktls --target curl --capture` enables plaintext stream capture by hooking OpenSSL application-data APIs such as `SSL_read` and `SSL_write`.

When capture is enabled, `fcktls`:

- prints request and response plaintext to stdout
- attempts HTTP parsing and pretty rendering first
- falls back to plain text or byte-oriented rendering when HTTP parsing fails
- writes plaintext stream artifacts alongside the session summary and keys

## Architectural Direction

The system uses a hybrid design.

- Runtime/process hooks are the control plane.
  They provide process attribution, TLS runtime identity, SNI, cipher, handshake state, and socket tuple resolution.
- Runtime plaintext hooks are the first data plane for the PoC.
  They provide decrypted application data directly at the TLS library boundary.
- Wire capture and userspace decryption remain the long-term fallback for runtimes where plaintext hooks are unavailable, too fragile, or too expensive.

For the OpenSSL `curl` PoC, the recommended fast path is:

1. pre-arm OpenSSL library uprobes globally
2. match target processes by basename at exec time
3. filter all probe events by matched PID and session
4. capture metadata and best-effort keys by default
5. capture plaintext request/response bytes only when `--capture` is enabled

## Why The PoC Does Not Need Stop-On-Exec

The existing OpenSSL and GnuTLS uprobe code in `../cmon` attaches to shared libraries globally by library path rather than per PID. That means the PoC does not need to halt matched `curl` processes before attaching hooks, as long as the relevant `libssl.so*` probes are armed before the handshake occurs.

Stop-on-exec remains relevant for later runtimes that require per-process attachment, especially Go `crypto/tls`, but it is intentionally deferred out of the first vertical slice.

## Components

### `cmd/fcktls`

CLI entrypoint that:

- parses flags such as `--target`, `--capture`, and `--cache-dir`
- validates privilege and kernel prerequisites
- constructs and starts the local daemon

### `pkg/runtime/processmon`

Process monitoring layer that:

- consumes exec and exit events
- resolves `/proc/<pid>/exe`
- matches the executable basename against the configured target
- maintains the set of tracked PIDs

### `pkg/runtime/openssl`

OpenSSL runtime integration layer derived from `../cmon` that:

- loads and manages OpenSSL uprobe programs
- attaches to discovered `libssl.so*` paths
- consumes handshake and state events
- optionally consumes plaintext read/write events

This package splits into two logical collectors:

- metadata and session-state collection
- optional plaintext capture

### `pkg/session`

Session correlation and lifecycle layer that:

- keys sessions by `(pid, ssl_ptr)` or a derived equivalent
- merges handshake, fd, socket, SNI, key, and plaintext events
- tracks completion and flush conditions
- exposes a normalized session record for rendering and artifact writing

### `pkg/render`

Terminal output layer that:

- prints concise live summaries in default mode
- prints formatted request/response sections in capture mode
- keeps rendering logic independent from eBPF and `/proc`

### `pkg/httpfmt`

Best-effort HTTP formatting layer that:

- classifies plaintext as request or response by direction and payload shape
- parses and pretty-renders HTTP headers and bodies when possible
- falls back to text or raw-byte framing when parsing fails

### `pkg/artifacts`

Artifact persistence layer that writes session outputs under:

- `~/.cache/fcktls/<session-id>/summary.json`
- `~/.cache/fcktls/<session-id>/keys.log`
- `~/.cache/fcktls/<session-id>/request.txt`
- `~/.cache/fcktls/<session-id>/response.txt`
- `~/.cache/fcktls/<session-id>/stream-client-to-server.bin`
- `~/.cache/fcktls/<session-id>/stream-server-to-client.bin`

The artifact writer always appends exact captured bytes to the directional binary stream files when capture is enabled. Human-readable `request.txt` and `response.txt` are written only when HTTP parsing succeeds well enough to classify the payload.

## Data Flow

1. `fcktls` starts as root on Linux.
2. The daemon starts process exec/exit monitoring.
3. The daemon discovers local `libssl.so*` paths and attaches OpenSSL uprobes to each supported library path.
4. A new process execs.
5. The process monitor resolves `/proc/<pid>/exe`; if the basename is `curl`, that PID becomes tracked.
6. OpenSSL handshake and state probes emit low-level events for all instrumented processes.
7. Userspace drops events for unmatched PIDs early.
8. For matched PIDs, the session layer accumulates:
   - process identity
   - OpenSSL session pointer
   - fd and socket tuple
   - SNI
   - TLS version
   - selected cipher suite
   - ALPN
   - certificate identities
   - best-effort key material
9. If `--capture` is enabled, `SSL_read` and `SSL_write` plaintext events are associated with the same session and directionally classified.
10. The render layer prints live summaries and, when enabled, prettified HTTP streams.
11. The artifact layer persists the session to the cache directory.
12. On process exit or session completion, in-memory state is flushed and cleaned up.

## Session Model

Each session record should carry enough information to unify future backends behind one abstraction. The initial OpenSSL-backed model should include:

- session identifier
- PID
- executable path
- library path and optional build identity
- OpenSSL session pointer
- source and destination tuple
- role, if inferable
- SNI
- TLS version
- selected cipher suite
- ALPN
- certificates
- key export status
- key log lines, when available
- capture status
- plaintext chunks, when capture is enabled
- timestamps for first seen and last seen

The session model must not assume that all runtimes will provide every field. Missing values are expected and must be explicitly representable.

## Matching Semantics

For the PoC, `--target curl` means:

- resolve the executable path via `/proc/<pid>/exe`
- compare the basename of the resolved executable to the configured target string

This is intentionally narrower than argv or shell-command matching. The PoC supports basename matching only.

## Key Export Semantics

Key export is required as a user-facing feature, but only on a best-effort basis for the PoC.

Per matched session, the tool must:

- attempt to export Wireshark-usable key log material
- indicate clearly whether key export succeeded
- persist any exported material to an artifact file
- avoid treating key export failure as a fatal session error

The stdout summary and `summary.json` must make the status explicit, for example:

- `available`
- `unavailable`
- `partial`
- `error`

## Plaintext Capture Semantics

Plaintext capture is disabled by default and enabled via `--capture`.

When enabled, the runtime layer should hook OpenSSL application-data boundaries, starting with `SSL_read` and `SSL_write`. The resulting plaintext must be handled as directional stream data tied to a session.

Rendering rules:

- attempt HTTP parsing first
- render requests and responses separately when possible
- preserve exact captured bytes in artifacts even if display output is normalized or prettified
- provide a fallback output mode when the payload is not valid HTTP

Resource rules:

- keep memory usage bounded by streaming artifacts to disk incrementally
- avoid retaining arbitrarily large response bodies in memory
- let stdout rendering truncate or summarize very large bodies if needed while preserving artifacts on disk

## Filesystem Layout

The default artifact root is:

- `~/.cache/fcktls`

Each session gets its own directory:

- `~/.cache/fcktls/<session-id>/`

Each session directory contains:

- `summary.json`
- `keys.log`
- `request.txt` when HTTP request rendering succeeds
- `response.txt` when HTTP response rendering succeeds
- `stream-client-to-server.bin` when capture is enabled and client-to-server bytes are observed
- `stream-server-to-client.bin` when capture is enabled and server-to-client bytes are observed

The PoC does not maintain process-global artifact files. Per-session artifacts are the source of truth.

## Failure Handling

### Startup failures

- If required privileges or kernel features are missing, fail fast with a clear diagnostic.
- If compiled eBPF objects are missing, fail fast with a clear build instruction.

### Runtime degradation

- If OpenSSL library discovery finds no `libssl.so*`, remain running and retry discovery periodically.
- If a matched `curl` does not use OpenSSL, emit an unsupported-runtime note for that PID and write it into the session summary.
- If plaintext capture hooks fail, continue emitting metadata.
- If key export fails, continue emitting metadata and optional plaintext capture.

### Session cleanup

- Process exit should flush pending session state and finalize artifacts.
- Partial sessions must still produce a `summary.json` when enough identifying context exists.
- Unmatched-process events should be dropped without user-visible noise.

## Performance Expectations

The PoC should bias toward correctness and debuggability over maximal throughput, but it must still avoid obvious host-wide overhead.

Important constraints:

- only matched PIDs should produce rich userspace processing
- plaintext capture must be opt-in
- artifact writing must stream rather than accumulate large buffers
- global OpenSSL probes are acceptable for the PoC because userspace filtering sharply narrows retained work

The design explicitly accepts that the OpenSSL PoC is not yet the final performance model for all runtimes.

## Reuse From `../cmon`

The PoC should reuse the working `../cmon` code wherever practical, especially:

- process exec/exit event monitoring
- native target discovery
- OpenSSL uprobe loaders and attach helpers
- socket tuple resolution via pidfd and inherited fd lookup
- existing OpenSSL metadata extraction logic

The new codebase should copy or adapt only the seams needed for a single-host debugging tool rather than bringing in the full agent, inventory, gRPC, or Kubernetes architecture.

## Testing Strategy

### Unit tests

- process basename matching
- session correlation and cleanup
- cache-directory artifact layout
- stdout rendering
- HTTP pretty-printing and fallback rendering
- key export status handling

### Integration tests

Add a local integration test that runs an OpenSSL-backed client/server roundtrip and verifies:

- a matched `curl` PID is detected
- TLS metadata is emitted
- artifact files are created under a temporary cache root
- `--capture` produces plaintext request and response outputs

The integration test should not depend on future generic stop-on-exec or tc-based wire capture.

## Future Extensions

Once the OpenSSL `curl` PoC is working, the next architectural expansions are:

1. add GnuTLS and Go runtime-specific adapters behind the same session model
2. introduce stop-on-exec only for runtimes that require PID-specific attach
3. add wire-capture plus userspace decryption as a fallback data plane
4. add richer matchers by target path, destination, or process attributes
5. add session export formats optimized for external tools such as Wireshark

The key architectural invariant is that users interact with one debugger model, while backends are free to supply metadata, keys, plaintext, or wire data through a common session abstraction.
