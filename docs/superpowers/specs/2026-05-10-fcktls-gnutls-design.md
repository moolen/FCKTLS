# FCKTLS GnuTLS Design

## Goal

Add a second runtime slice to `fcktls` for GnuTLS-based clients, starting with a user flow like:

- `fcktls --target wget`
- `wget https://example.com`

The GnuTLS slice must preserve the same user-facing model as the OpenSSL slice:

- basename process matching
- metadata and best-effort key export by default
- optional plaintext capture with `--capture`
- live stdout rendering
- per-session artifacts under `~/.cache/fcktls`

## Non-Goals

This slice does not need to:

- implement Go `crypto/tls` support yet
- add stop-on-exec for GnuTLS
- guarantee key export for all GnuTLS sessions
- redesign the existing OpenSSL session model or CLI
- introduce wire capture or tc hooks

## Recommended Approach

The recommended approach is to reuse the same high-level architecture already proven for OpenSSL:

1. pre-attach GnuTLS uprobes globally to discovered `libgnutls.so*` libraries
2. keep process matching by basename via exec events
3. filter GnuTLS events in userspace by matched PID
4. merge GnuTLS metadata, best-effort keys, and optional plaintext into the existing session model

This is preferred over a metadata-only slice because it keeps one consistent runtime UX and makes `--capture` meaningful across runtimes.

## User Experience

### Default mode

`fcktls --target wget` starts the daemon and:

- monitors process exec and exit events
- pre-attaches GnuTLS probes to discovered `libgnutls.so*`
- tracks PIDs whose basename matches `wget`
- prints GnuTLS session metadata for matched processes
- attempts key export on a best-effort basis
- writes artifacts under `~/.cache/fcktls`

The live metadata output should include, when available:

- PID and executable path
- source and destination tuple
- SNI
- negotiated protocol version
- cipher information or GnuTLS priority details
- resumed state
- verify status
- negotiated group
- key export status

### Capture mode

`fcktls --target wget --capture` additionally captures plaintext record traffic at the GnuTLS library boundary.

When capture is enabled:

- stdout attempts HTTP rendering first
- request and response streams are shown directionally when parseable
- exact plaintext bytes are still persisted as artifacts even if the display output is prettified

## Attachment Model

GnuTLS should use the same shared-library attachment model as OpenSSL for v1.

- no stop-on-exec
- no per-PID attach requirement
- pre-arm the shared library once per discovered path
- discard events for unmatched processes in userspace

This matches the existing `../cmon` GnuTLS collector shape and avoids unnecessary complexity for the first slice.

## Components

### `pkg/ebpf/gnutls.go`

Adapts the reusable pieces from `../cmon/pkg/ebpf/gnutls_tls.go` into FCKTLS:

- event structs
- decode helpers
- library attach logic
- loader lifecycle

### `pkg/ebpf/bpf/gnutls_uprobe.c`

Provides the GnuTLS BPF programs for:

- handshake entry and return
- transport fd binding
- server-name setup
- priority setup
- resumed-session checks
- verify-status reads
- negotiated-group reads
- optional record send/receive capture for plaintext mode

### `pkg/fcktls/daemon.go`

Extends the daemon loop to:

- start a GnuTLS event reader
- attach discovered `libgnutls.so*`
- route matched GnuTLS events into the shared session store
- keep OpenSSL and GnuTLS readers independent but normalized at the session-update boundary

### Shared packages

The following packages should remain runtime-agnostic and be reused:

- `pkg/fcktls/session_store.go`
- `pkg/fcktls/render.go`
- `pkg/fcktls/httpfmt.go`
- `pkg/fcktls/artifacts.go`

## Data Flow

1. `fcktls` starts and attaches process exec/exit monitoring.
2. The daemon discovers `libgnutls.so*` and attaches GnuTLS uprobes once per path.
3. A new process execs.
4. If the resolved basename matches the target, such as `wget`, the PID becomes tracked.
5. GnuTLS probes emit events such as:
   - handshake results
   - session pointer
   - transport fd association
   - configured SNI
   - configured priority string
   - resumed-session checks
   - verify status
   - negotiated group
   - optional plaintext record traffic
6. The daemon drops events for unmatched PIDs.
7. Matched events are merged into the shared session model.
8. Metadata is printed by default.
9. Plaintext capture is rendered only when `--capture` is enabled.
10. Artifacts are written under the normal per-session cache directory.

## Session Model Expectations

The existing session model is already flexible enough for GnuTLS. This slice should populate:

- session identifier
- PID and executable path
- library path
- source and destination tuple
- SNI
- TLS version if available
- cipher or priority information if available
- resumed state
- verify status
- negotiated group
- best-effort key status
- plaintext chunks when enabled

Fields unavailable from GnuTLS must remain explicitly absent rather than invented.

## Matching Semantics

The GnuTLS slice keeps the same matching semantics as OpenSSL:

- resolve `/proc/<pid>/exe`
- compare basename to the configured target

No argv or command-line matching is added in this slice.

## Key Export Semantics

Key export remains best-effort.

For each matched GnuTLS session:

- attempt export when a safe runtime hook exists
- clearly record whether it succeeded
- persist any captured key-log material to `keys.log`
- never treat key-export failure as a fatal session error

Expected states remain:

- `available`
- `unavailable`
- `partial`
- `error`

## Plaintext Capture Semantics

Plaintext capture is optional and only enabled with `--capture`.

The initial GnuTLS capture path should hook record-level send/receive APIs where practical and emit directional plaintext chunks. Those chunks should flow through the same formatting and artifact layers already used for OpenSSL.

Rendering rules remain unchanged:

- try HTTP parsing first
- fall back to raw text or byte-oriented rendering when parsing fails
- preserve exact bytes in artifacts

## Errors

- If no `libgnutls.so*` is found, stay running and retry discovery periodically.
- If a matched target never emits GnuTLS or OpenSSL events, report the existing unsupported-runtime summary.
- If metadata is available but key export is not, preserve the metadata and make the key status explicit.
- If plaintext capture symbols are unavailable in the installed GnuTLS, keep metadata-only behavior and record that capture is unavailable.

## Testing

Add tests in three layers.

### `pkg/ebpf`

- decode tests for GnuTLS event structs
- attach-spec tests for expected symbol coverage

### `pkg/fcktls`

- daemon unit tests for GnuTLS metadata merge
- daemon unit tests for optional capture flow
- artifact and render assertions via the shared session model

### Root-only integration

Add at least one root-only integration test using a real GnuTLS-linked client, preferably `wget`, against a local TLS server. The test should verify:

- basename match works
- metadata is emitted
- artifacts are created
- `--capture` yields plaintext if the chosen GnuTLS record hooks are available on the host

## Reuse From `../cmon`

The slice should intentionally reuse the existing `../cmon` GnuTLS work where practical:

- GnuTLS library discovery patterns
- handshake and metadata probe structure
- remote runtime-state reading strategy
- attach-path handling for shared libraries

FCKTLS should only add what is needed to fit that into the local session, rendering, and artifact model.

## Deferred Work

After the GnuTLS slice:

1. add Go `crypto/tls` as a separate per-binary attachment slice
2. revisit whether key export can be made stronger across all runtimes
3. decide whether any runtime needs stop-on-exec instead of the shared-library pre-attach model
