package fcktls

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/moolen/FCKTLS/pkg/ebpf"
)

func TestDaemonFinalizesMatchedMetadataSession(t *testing.T) {
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	var stdout bytes.Buffer
	cfg, err := NewConfig("curl", false, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	d := &Daemon{
		Config:  cfg,
		OpenSSL: &stubOpenSSLLoader{attachedPaths: []string{"/usr/lib/libssl.so.3"}},
		Monitor: NewProcessMonitor("curl", staticExeResolver{
			paths: map[int]string{101: "/usr/bin/curl"},
		}),
		Now:       func() time.Time { return now },
		Stdout:    &stdout,
		Artifacts: NewArtifactWriter(cfg.CacheRoot),
		Store:     NewSessionStore(),
	}
	tracked := map[int]ProcessMatch{
		101: {PID: 101, ExePath: "/usr/bin/curl", Basename: "curl"},
	}
	seen := map[int]bool{101: false}
	fds := make(map[SessionKey]int)
	exited := map[int]time.Time{101: now.Add(time.Second)}

	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:        101,
		SessionPtr: 0x1,
		ProbeKind:  ebpf.OpenSSLProbeKindSSLConnect,
		EventType:  ebpf.OpenSSLEventTypeSetFD,
		Value:      9,
	}, tracked, seen, fds)
	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:        101,
		SessionPtr: 0x1,
		ProbeKind:  ebpf.OpenSSLProbeKindSSLConnect,
		EventType:  ebpf.OpenSSLEventTypeSetSNI,
		SNIBytes:   toSNIBytes("example.com"),
	}, tracked, seen, fds)
	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:        101,
		SessionPtr: 0x1,
		EventType:  ebpf.OpenSSLEventTypeSetGroups,
		SNIBytes:   toSNIBytes("X25519:P-256"),
	}, tracked, seen, fds)
	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:        101,
		SessionPtr: 0x1,
		EventType:  ebpf.OpenSSLEventTypeSetVerify,
		Value:      3,
	}, tracked, seen, fds)
	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:        101,
		SessionPtr: 0x1,
		EventType:  ebpf.OpenSSLEventTypeSessionReused,
		Value:      0,
	}, tracked, seen, fds)
	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:        101,
		SessionPtr: 0x1,
		EventType:  ebpf.OpenSSLEventTypeVerifyResult,
		Value:      0,
	}, tracked, seen, fds)
	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:        101,
		SessionPtr: 0x1,
		EventType:  ebpf.OpenSSLEventTypeNegotiatedGroup,
		Value:      1034,
	}, tracked, seen, fds)
	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:        101,
		SessionPtr: 0x1,
		ProbeKind:  ebpf.OpenSSLProbeKindSSLConnect,
		EventType:  ebpf.OpenSSLEventTypeHandshake,
		Value:      1,
	}, tracked, seen, fds)
	d.flushExited(tracked, seen, fds, exited, time.Unix(1<<62, 0))

	for _, want := range []string{
		"example.com",
		"fd=9",
		"groups=X25519:P-256",
		"verify_mode=3",
		"session_reused=false",
		"verify_result=0",
		"negotiated_group=1034",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	summaryPath := filepath.Join(cfg.CacheRoot, "pid-101-ssl-0x1", "summary.json")
	if _, err := os.Stat(summaryPath); err != nil {
		t.Fatalf("summary.json stat error = %v", err)
	}

	rawSummary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("ReadFile(summary.json) error = %v", err)
	}

	var summary struct {
		Metadata SessionMetadata `json:"metadata"`
	}
	if err := json.Unmarshal(rawSummary, &summary); err != nil {
		t.Fatalf("Unmarshal(summary.json) error = %v", err)
	}

	if summary.Metadata.SocketFD == nil || *summary.Metadata.SocketFD != 9 {
		t.Fatalf("socket_fd = %v, want 9", summary.Metadata.SocketFD)
	}
	if got, want := summary.Metadata.Groups, "X25519:P-256"; got != want {
		t.Fatalf("groups = %q, want %q", got, want)
	}
	if summary.Metadata.VerifyMode == nil || *summary.Metadata.VerifyMode != 3 {
		t.Fatalf("verify_mode = %v, want 3", summary.Metadata.VerifyMode)
	}
	if summary.Metadata.SessionReused == nil || *summary.Metadata.SessionReused {
		t.Fatalf("session_reused = %v, want false", summary.Metadata.SessionReused)
	}
	if summary.Metadata.VerifyResult == nil || *summary.Metadata.VerifyResult != 0 {
		t.Fatalf("verify_result = %v, want 0", summary.Metadata.VerifyResult)
	}
	if summary.Metadata.NegotiatedGroup == nil || *summary.Metadata.NegotiatedGroup != 1034 {
		t.Fatalf("negotiated_group = %v, want 1034", summary.Metadata.NegotiatedGroup)
	}
}

func TestDaemonFinalizesCaptureSession(t *testing.T) {
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	var stdout bytes.Buffer
	cfg, err := NewConfig("curl", true, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	d := &Daemon{
		Config:  cfg,
		OpenSSL: &stubOpenSSLLoader{attachedPaths: []string{"/usr/lib/libssl.so.3"}},
		Monitor: NewProcessMonitor("curl", staticExeResolver{
			paths: map[int]string{202: "/usr/bin/curl"},
		}),
		Now:       func() time.Time { return now },
		Stdout:    &stdout,
		Artifacts: NewArtifactWriter(cfg.CacheRoot),
		Store:     NewSessionStore(),
	}
	tracked := map[int]ProcessMatch{
		202: {PID: 202, ExePath: "/usr/bin/curl", Basename: "curl"},
	}
	seen := map[int]bool{202: false}
	fds := make(map[SessionKey]int)
	exited := map[int]time.Time{202: now.Add(time.Second)}

	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:        202,
		SessionPtr: 0x2,
		ProbeKind:  ebpf.OpenSSLProbeKindSSLConnect,
		EventType:  ebpf.OpenSSLEventTypeHandshake,
		Value:      1,
	}, tracked, seen, fds)
	d.handleAppDataEvent(newAppDataEvent(202, 0x2, ebpf.OpenSSLAppDataDirectionWrite, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")), tracked)
	d.handleAppDataEvent(newAppDataEvent(202, 0x2, ebpf.OpenSSLAppDataDirectionRead, []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")), tracked)
	d.flushExited(tracked, seen, fds, exited, time.Unix(1<<62, 0))

	if !strings.Contains(stdout.String(), "GET / HTTP/1.1") || !strings.Contains(stdout.String(), "HTTP/1.1 200 OK") {
		t.Fatalf("stdout = %q, want capture output", stdout.String())
	}
	requestPath := filepath.Join(cfg.CacheRoot, "pid-202-ssl-0x2", "request.txt")
	if _, err := os.Stat(requestPath); err != nil {
		t.Fatalf("request.txt stat error = %v", err)
	}
}

func TestDaemonUsesInspectorForNegotiatedMetadataAndKeys(t *testing.T) {
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	var stdout bytes.Buffer
	cfg, err := NewConfig("curl", false, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	d := &Daemon{
		Config:  cfg,
		OpenSSL: &stubOpenSSLLoader{attachedPaths: []string{"/usr/lib/libssl.so.3"}},
		Inspector: stubInspector{inspection: OpenSSLInspection{
			TLSVersion:    "TLSv1.3",
			CipherSuite:   "TLS_AES_128_GCM_SHA256",
			ALPN:          "h2",
			Certificates:  []CertificateSummary{{Subject: "/CN=example.com", Issuer: "/CN=Example CA"}},
			KeyLogLines:   []string{"CLIENT_TRAFFIC_SECRET_0 abc def"},
			KeyStatus:     KeyStatusAvailable,
			KeyStatusNote: "openssl key log exported",
		}},
		Monitor: NewProcessMonitor("curl", staticExeResolver{
			paths: map[int]string{404: "/usr/bin/curl"},
		}),
		Now:       func() time.Time { return now },
		Stdout:    &stdout,
		Artifacts: NewArtifactWriter(cfg.CacheRoot),
		Store:     NewSessionStore(),
	}
	tracked := map[int]ProcessMatch{
		404: {PID: 404, ExePath: "/usr/bin/curl", Basename: "curl"},
	}
	seen := map[int]bool{404: false}
	fds := make(map[SessionKey]int)
	exited := map[int]time.Time{404: now.Add(time.Second)}

	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:         404,
		TimestampNS: uint64(now.UnixNano()),
		SessionPtr:  0x4,
		ProbeKind:   ebpf.OpenSSLProbeKindSSLConnect,
		EventType:   ebpf.OpenSSLEventTypeHandshake,
		Value:       1,
	}, tracked, seen, fds)
	d.flushExited(tracked, seen, fds, exited, time.Unix(1<<62, 0))

	for _, want := range []string{"tls=TLSv1.3", "cipher=TLS_AES_128_GCM_SHA256", "alpn=h2", "certs=1", "key_status=available"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}

	keysPath := filepath.Join(cfg.CacheRoot, "pid-404-ssl-0x4", "keys.log")
	data, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatalf("ReadFile(keys.log) error = %v", err)
	}
	if !strings.Contains(string(data), "CLIENT_TRAFFIC_SECRET_0 abc def") {
		t.Fatalf("keys.log = %q, want key log line", data)
	}
}

func TestDaemonRetriesInspectionAfterInitialFailure(t *testing.T) {
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	cfg, err := NewConfig("curl", false, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	inspector := &sequenceInspector{
		results: []inspectionResult{
			{err: errors.New("ptrace attach: no such process")},
			{inspection: OpenSSLInspection{
				TLSVersion:    "TLSv1.2",
				CipherSuite:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				KeyLogLines:   []string{"CLIENT_RANDOM abc def"},
				KeyStatus:     KeyStatusAvailable,
				KeyStatusNote: "openssl key log exported",
			}},
		},
	}

	d := &Daemon{
		Config:    cfg,
		OpenSSL:   &stubOpenSSLLoader{attachedPaths: []string{"/usr/lib/libssl.so.3"}},
		Inspector: inspector,
		Monitor: NewProcessMonitor("curl", staticExeResolver{
			paths: map[int]string{606: "/usr/bin/curl"},
		}),
		Now:       func() time.Time { return now },
		Stdout:    io.Discard,
		Artifacts: NewArtifactWriter(cfg.CacheRoot),
		Store:     NewSessionStore(),
	}
	tracked := map[int]ProcessMatch{
		606: {PID: 606, ExePath: "/usr/bin/curl", Basename: "curl"},
	}
	seen := map[int]bool{606: false}
	fds := make(map[SessionKey]int)

	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:         606,
		TimestampNS: uint64(now.UnixNano()),
		SessionPtr:  0x6,
		ProbeKind:   ebpf.OpenSSLProbeKindSSLConnect,
		EventType:   ebpf.OpenSSLEventTypeHandshake,
		Value:       1,
	}, tracked, seen, fds)
	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:         606,
		TimestampNS: uint64(now.Add(time.Millisecond).UnixNano()),
		SessionPtr:  0x6,
		EventType:   ebpf.OpenSSLEventTypeVerifyResult,
		Value:       0,
	}, tracked, seen, fds)

	snapshot, ok := d.Store.Finalize(SessionKey{PID: 606, SSLPointer: 0x6}, now.Add(2*time.Millisecond))
	if !ok {
		t.Fatal("Finalize() ok = false, want true")
	}
	if got, want := inspector.calls, 2; got != want {
		t.Fatalf("inspector calls = %d, want %d", got, want)
	}
	if got, want := snapshot.Metadata.TLSVersion, "TLSv1.2"; got != want {
		t.Fatalf("TLSVersion = %q, want %q", got, want)
	}
	if got, want := snapshot.Metadata.KeyStatus, KeyStatusAvailable; got != want {
		t.Fatalf("KeyStatus = %q, want %q", got, want)
	}
	if got, want := len(snapshot.Metadata.KeyLogLines), 1; got != want {
		t.Fatalf("len(KeyLogLines) = %d, want %d", got, want)
	}
}

func TestDaemonRetriesTLS12InspectionWhenMetadataArrivesBeforeKeys(t *testing.T) {
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	cfg, err := NewConfig("curl", false, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	inspector := &sequenceInspector{
		results: []inspectionResult{
			{inspection: OpenSSLInspection{
				TLSVersion:    "TLSv1.2",
				CipherSuite:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				KeyStatus:     KeyStatusUnavailable,
				KeyStatusNote: "key export unavailable",
			}},
			{inspection: OpenSSLInspection{
				TLSVersion:    "TLSv1.2",
				CipherSuite:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				KeyLogLines:   []string{"CLIENT_RANDOM abc def"},
				KeyStatus:     KeyStatusAvailable,
				KeyStatusNote: "openssl key log exported",
			}},
		},
	}

	d := &Daemon{
		Config:    cfg,
		OpenSSL:   &stubOpenSSLLoader{attachedPaths: []string{"/usr/lib/libssl.so.3"}},
		Inspector: inspector,
		Monitor: NewProcessMonitor("curl", staticExeResolver{
			paths: map[int]string{707: "/usr/bin/curl"},
		}),
		Now:       func() time.Time { return now },
		Stdout:    io.Discard,
		Artifacts: NewArtifactWriter(cfg.CacheRoot),
		Store:     NewSessionStore(),
	}
	tracked := map[int]ProcessMatch{
		707: {PID: 707, ExePath: "/usr/bin/curl", Basename: "curl"},
	}
	seen := map[int]bool{707: false}
	fds := make(map[SessionKey]int)

	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:         707,
		TimestampNS: uint64(now.UnixNano()),
		SessionPtr:  0x7,
		ProbeKind:   ebpf.OpenSSLProbeKindSSLConnect,
		EventType:   ebpf.OpenSSLEventTypeHandshake,
		Value:       1,
	}, tracked, seen, fds)
	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:         707,
		TimestampNS: uint64(now.Add(time.Millisecond).UnixNano()),
		SessionPtr:  0x7,
		EventType:   ebpf.OpenSSLEventTypeVerifyResult,
		Value:       0,
	}, tracked, seen, fds)

	snapshot, ok := d.Store.Finalize(SessionKey{PID: 707, SSLPointer: 0x7}, now.Add(2*time.Millisecond))
	if !ok {
		t.Fatal("Finalize() ok = false, want true")
	}
	if got, want := inspector.calls, 2; got != want {
		t.Fatalf("inspector calls = %d, want %d", got, want)
	}
	if got, want := snapshot.Metadata.KeyStatus, KeyStatusAvailable; got != want {
		t.Fatalf("KeyStatus = %q, want %q", got, want)
	}
	if got, want := len(snapshot.Metadata.KeyLogLines), 1; got != want {
		t.Fatalf("len(KeyLogLines) = %d, want %d", got, want)
	}
}

func TestDaemonMergesTLS13KeyMaterialEvent(t *testing.T) {
	now := time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)
	cfg, err := NewConfig("curl", false, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	d := &Daemon{
		Config:    cfg,
		OpenSSL:   &stubOpenSSLLoader{attachedPaths: []string{"/usr/lib/libssl.so.3"}},
		Monitor:   NewProcessMonitor("curl", staticExeResolver{paths: map[int]string{808: "/usr/bin/curl"}}),
		Now:       func() time.Time { return now },
		Stdout:    io.Discard,
		Artifacts: NewArtifactWriter(cfg.CacheRoot),
		Store:     NewSessionStore(),
	}
	tracked := map[int]ProcessMatch{
		808: {PID: 808, ExePath: "/usr/bin/curl", Basename: "curl"},
	}
	seen := map[int]bool{808: false}
	fds := make(map[SessionKey]int)

	var random [32]byte
	for i := range random {
		random[i] = byte(i)
	}
	var secret [64]byte
	for i := 0; i < 48; i++ {
		secret[i] = byte(0xa0 + i)
	}

	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:                808,
		TimestampNS:        uint64(now.UnixNano()),
		SessionPtr:         0x8,
		ProbeKind:          ebpf.OpenSSLProbeKindSSLConnect,
		EventType:          ebpf.OpenSSLEventTypeKeyMaterial,
		ClientRandomLength: 32,
		SecretLength:       48,
		SNIBytes:           toSNIBytes("CLIENT_TRAFFIC_SECRET_0"),
		ClientRandom:       random,
		Secret:             secret,
	}, tracked, seen, fds)

	snapshot, ok := d.Store.Finalize(SessionKey{PID: 808, SSLPointer: 0x8}, now.Add(time.Millisecond))
	if !ok {
		t.Fatal("Finalize() ok = false, want true")
	}
	if got, want := snapshot.Metadata.KeyStatus, KeyStatusAvailable; got != want {
		t.Fatalf("KeyStatus = %q, want %q", got, want)
	}
	if got, want := len(snapshot.Metadata.KeyLogLines), 1; got != want {
		t.Fatalf("len(KeyLogLines) = %d, want %d", got, want)
	}
	if got, want := snapshot.Metadata.KeyLogLines[0], "CLIENT_TRAFFIC_SECRET_0 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"; got != want {
		t.Fatalf("KeyLogLines[0] = %q, want %q", got, want)
	}
}

func TestDaemonInspectsOnTLS13KeyMaterialEvent(t *testing.T) {
	now := time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)
	cfg, err := NewConfig("curl", false, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	inspector := &sequenceInspector{
		results: []inspectionResult{
			{inspection: OpenSSLInspection{
				TLSVersion:    "TLSv1.3",
				CipherSuite:   "TLS_AES_256_GCM_SHA384",
				KeyStatus:     KeyStatusUnavailable,
				KeyStatusNote: "TLS 1.3 key export unavailable via OpenSSL public getters; requires keylog callback or deeper hooks",
			}},
		},
	}

	d := &Daemon{
		Config:    cfg,
		OpenSSL:   &stubOpenSSLLoader{attachedPaths: []string{"/usr/lib/libssl.so.3"}},
		Inspector: inspector,
		Monitor:   NewProcessMonitor("curl", staticExeResolver{paths: map[int]string{909: "/usr/bin/curl"}}),
		Now:       func() time.Time { return now },
		Stdout:    io.Discard,
		Artifacts: NewArtifactWriter(cfg.CacheRoot),
		Store:     NewSessionStore(),
	}
	tracked := map[int]ProcessMatch{
		909: {PID: 909, ExePath: "/usr/bin/curl", Basename: "curl"},
	}
	seen := map[int]bool{909: false}
	fds := make(map[SessionKey]int)

	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:                909,
		TimestampNS:        uint64(now.UnixNano()),
		SessionPtr:         0x9,
		EventType:          ebpf.OpenSSLEventTypeKeyMaterial,
		ClientRandomLength: 32,
		SecretLength:       48,
		SNIBytes:           toSNIBytes("CLIENT_TRAFFIC_SECRET_0"),
	}, tracked, seen, fds)

	snapshot, ok := d.Store.Finalize(SessionKey{PID: 909, SSLPointer: 0x9}, now.Add(time.Millisecond))
	if !ok {
		t.Fatal("Finalize() ok = false, want true")
	}
	if got, want := inspector.calls, 1; got != want {
		t.Fatalf("inspector calls = %d, want %d", got, want)
	}
	if got, want := snapshot.Metadata.TLSVersion, "TLSv1.3"; got != want {
		t.Fatalf("TLSVersion = %q, want %q", got, want)
	}
}

func TestDaemonMergesGnuTLSMetadataEvent(t *testing.T) {
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	var stdout bytes.Buffer
	cfg, err := NewConfig("wget", false, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	d := &Daemon{
		Config: cfg,
		GnuTLS: &stubGnuTLSLoader{attachedPaths: []string{"/usr/lib/libgnutls.so.30"}},
		Monitor: NewProcessMonitor("wget", staticExeResolver{
			paths: map[int]string{707: "/usr/bin/wget"},
		}),
		Now:       func() time.Time { return now },
		Stdout:    &stdout,
		Artifacts: NewArtifactWriter(cfg.CacheRoot),
		Store:     NewSessionStore(),
	}
	tracked := map[int]ProcessMatch{
		707: {PID: 707, ExePath: "/usr/bin/wget", Basename: "wget"},
	}
	seen := map[int]bool{707: false}
	fds := make(map[SessionKey]int)
	exited := map[int]time.Time{707: now.Add(time.Second)}

	d.handleGnuTLSEvent(ebpf.GnuTLSEvent{
		PID:         707,
		TimestampNS: uint64(now.UnixNano()),
		SessionPtr:  0x7,
		EventType:   ebpf.GnuTLSEventTypeSetFD,
		Value:       11,
	}, tracked, seen, fds)
	d.handleGnuTLSEvent(ebpf.GnuTLSEvent{
		PID:         707,
		TimestampNS: uint64(now.UnixNano()),
		SessionPtr:  0x7,
		EventType:   ebpf.GnuTLSEventTypeSetSNI,
		Bytes:       toSNIBytes("example.com"),
	}, tracked, seen, fds)
	d.handleGnuTLSEvent(ebpf.GnuTLSEvent{
		PID:         707,
		TimestampNS: uint64(now.UnixNano()),
		SessionPtr:  0x7,
		EventType:   ebpf.GnuTLSEventTypeSetPriority,
		Bytes:       toSNIBytes("NORMAL:-VERS-TLS1.3"),
	}, tracked, seen, fds)
	d.handleGnuTLSEvent(ebpf.GnuTLSEvent{
		PID:         707,
		TimestampNS: uint64(now.UnixNano()),
		SessionPtr:  0x7,
		EventType:   ebpf.GnuTLSEventTypeSessionResumed,
		Value:       1,
	}, tracked, seen, fds)
	d.handleGnuTLSEvent(ebpf.GnuTLSEvent{
		PID:         707,
		TimestampNS: uint64(now.UnixNano()),
		SessionPtr:  0x7,
		EventType:   ebpf.GnuTLSEventTypeVerifyStatus,
		Value:       0,
	}, tracked, seen, fds)
	d.handleGnuTLSEvent(ebpf.GnuTLSEvent{
		PID:         707,
		TimestampNS: uint64(now.UnixNano()),
		SessionPtr:  0x7,
		EventType:   ebpf.GnuTLSEventTypeNegotiatedGroup,
		Value:       29,
	}, tracked, seen, fds)
	d.handleGnuTLSEvent(ebpf.GnuTLSEvent{
		PID:         707,
		TimestampNS: uint64(now.UnixNano()),
		SessionPtr:  0x7,
		EventType:   ebpf.GnuTLSEventTypeHandshake,
		Value:       0,
	}, tracked, seen, fds)
	d.flushExited(tracked, seen, fds, exited, time.Unix(1<<62, 0))

	for _, want := range []string{
		"example.com",
		"fd=11",
		"priority=NORMAL:-VERS-TLS1.3",
		"session_reused=true",
		"verify_result=0",
		"negotiated_group=29",
		"key_status=unavailable",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}

	summaryPath := filepath.Join(cfg.CacheRoot, "pid-707-ssl-0x7", "summary.json")
	rawSummary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("ReadFile(summary.json) error = %v", err)
	}

	var summary struct {
		Metadata SessionMetadata `json:"metadata"`
	}
	if err := json.Unmarshal(rawSummary, &summary); err != nil {
		t.Fatalf("Unmarshal(summary.json) error = %v", err)
	}
	if summary.Metadata.SocketFD == nil || *summary.Metadata.SocketFD != 11 {
		t.Fatalf("socket_fd = %v, want 11", summary.Metadata.SocketFD)
	}
	if got, want := summary.Metadata.SNI, "example.com"; got != want {
		t.Fatalf("SNI = %q, want %q", got, want)
	}
	if got, want := summary.Metadata.Priority, "NORMAL:-VERS-TLS1.3"; got != want {
		t.Fatalf("Priority = %q, want %q", got, want)
	}
	if got, want := summary.Metadata.LibraryPath, "/usr/lib/libgnutls.so.30"; got != want {
		t.Fatalf("LibraryPath = %q, want %q", got, want)
	}
}

func TestDaemonCapturesGnuTLSPlaintext(t *testing.T) {
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	var stdout bytes.Buffer
	cfg, err := NewConfig("wget", true, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	d := &Daemon{
		Config: cfg,
		GnuTLS: &stubGnuTLSLoader{attachedPaths: []string{"/usr/lib/libgnutls.so.30"}},
		Monitor: NewProcessMonitor("wget", staticExeResolver{
			paths: map[int]string{808: "/usr/bin/wget"},
		}),
		Now:       func() time.Time { return now },
		Stdout:    &stdout,
		Artifacts: NewArtifactWriter(cfg.CacheRoot),
		Store:     NewSessionStore(),
	}
	tracked := map[int]ProcessMatch{
		808: {PID: 808, ExePath: "/usr/bin/wget", Basename: "wget"},
	}
	seen := map[int]bool{808: false}
	fds := make(map[SessionKey]int)
	exited := map[int]time.Time{808: now.Add(time.Second)}

	d.handleGnuTLSEvent(ebpf.GnuTLSEvent{
		PID:         808,
		TimestampNS: uint64(now.UnixNano()),
		SessionPtr:  0x8,
		EventType:   ebpf.GnuTLSEventTypeHandshake,
		Value:       0,
	}, tracked, seen, fds)
	d.handleGnuTLSAppDataEvent(newGnuTLSAppDataEvent(808, 0x8, ebpf.GnuTLSAppDataDirectionWrite, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")), tracked)
	d.handleGnuTLSAppDataEvent(newGnuTLSAppDataEvent(808, 0x8, ebpf.GnuTLSAppDataDirectionRead, []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")), tracked)
	d.flushExited(tracked, seen, fds, exited, time.Unix(1<<62, 0))

	if !strings.Contains(stdout.String(), "GET / HTTP/1.1") || !strings.Contains(stdout.String(), "HTTP/1.1 200 OK") {
		t.Fatalf("stdout = %q, want capture output", stdout.String())
	}

	requestPath := filepath.Join(cfg.CacheRoot, "pid-808-ssl-0x8", "request.txt")
	if _, err := os.Stat(requestPath); err != nil {
		t.Fatalf("request.txt stat error = %v", err)
	}
}

func TestDaemonExecGatesSupportedGoTLSProcess(t *testing.T) {
	now := time.Date(2026, 5, 10, 13, 0, 0, 0, time.UTC)
	cfg, err := NewConfig("go-client", false, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	goLoader := &stubGoTLSLoader{}
	var calls []string
	d := &Daemon{
		Config:  cfg,
		OpenSSL: &stubOpenSSLLoader{attachedPaths: []string{"/usr/lib/libssl.so.3"}},
		GoTLS:   goLoader,
		GoExecGate: &GoExecGate{
			Loader: goLoader,
			Inspect: func(path string) (goBinaryInspection, error) {
				calls = append(calls, "inspect:"+path)
				return goBinaryInspection{
					IsGoBinary: true,
					BinaryPath: "/opt/go-client",
					Symbols: map[string]struct{}{
						goTLSClientHandshakeSymbol: {},
						goTLSConnectionStateSymbol: {},
					},
				}, nil
			},
			StopProcess: func(pid int) error {
				calls = append(calls, "stop")
				return nil
			},
			ResumeProcess: func(pid int) error {
				calls = append(calls, "resume")
				return nil
			},
		},
		Monitor: NewProcessMonitor("go-client", staticExeResolver{
			paths: map[int]string{909: "/usr/bin/go-client"},
		}),
		Now:   func() time.Time { return now },
		Store: NewSessionStore(),
	}
	tracked := make(map[int]ProcessMatch)
	seen := make(map[int]bool)
	fds := make(map[SessionKey]int)
	exited := make(map[int]time.Time)

	d.handleProcessEvent(ebpf.ProcessEvent{
		PID:         909,
		EventType:   ebpf.ProcessEventTypeExec,
		TimestampNS: uint64(now.UnixNano()),
	}, tracked, seen, fds, exited)

	match, ok := tracked[909]
	if !ok {
		t.Fatal("tracked pid missing after exec")
	}
	if got, want := match.ExePath, "/usr/bin/go-client"; got != want {
		t.Fatalf("ExePath = %q, want %q", got, want)
	}
	if got, want := calls, []string{
		"inspect:/usr/bin/go-client",
		"stop",
		"resume",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("call order = %#v, want %#v", got, want)
	}
	if got, want := len(goLoader.attachCalls), 1; got != want {
		t.Fatalf("len(attachCalls) = %d, want %d", got, want)
	}
	if got, want := goLoader.attachCalls[0], (goAttachCall{pid: 909, executablePath: "/opt/go-client"}); got != want {
		t.Fatalf("attach call = %#v, want %#v", got, want)
	}
}

func TestDaemonSkipsGoTLSGateForUnsupportedGoBinary(t *testing.T) {
	now := time.Date(2026, 5, 10, 13, 0, 0, 0, time.UTC)
	cfg, err := NewConfig("go-client", false, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	goLoader := &stubGoTLSLoader{}
	var calls []string
	d := &Daemon{
		Config:  cfg,
		OpenSSL: &stubOpenSSLLoader{attachedPaths: []string{"/usr/lib/libssl.so.3"}},
		GoTLS:   goLoader,
		GoExecGate: &GoExecGate{
			Loader: goLoader,
			Inspect: func(path string) (goBinaryInspection, error) {
				calls = append(calls, "inspect:"+path)
				return goBinaryInspection{
					IsGoBinary: true,
					Symbols: map[string]struct{}{
						"main.main": {},
					},
				}, nil
			},
			StopProcess: func(pid int) error {
				calls = append(calls, "stop")
				return nil
			},
			ResumeProcess: func(pid int) error {
				calls = append(calls, "resume")
				return nil
			},
		},
		Monitor: NewProcessMonitor("go-client", staticExeResolver{
			paths: map[int]string{910: "/usr/bin/go-client"},
		}),
		Now:   func() time.Time { return now },
		Store: NewSessionStore(),
	}
	tracked := make(map[int]ProcessMatch)
	seen := make(map[int]bool)
	fds := make(map[SessionKey]int)
	exited := make(map[int]time.Time)

	d.handleProcessEvent(ebpf.ProcessEvent{
		PID:         910,
		EventType:   ebpf.ProcessEventTypeExec,
		TimestampNS: uint64(now.UnixNano()),
	}, tracked, seen, fds, exited)

	if _, ok := tracked[910]; !ok {
		t.Fatal("tracked pid missing after exec")
	}
	if got, want := calls, []string{"inspect:/usr/bin/go-client"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("call order = %#v, want %#v", got, want)
	}
	if len(goLoader.attachCalls) != 0 {
		t.Fatalf("attachCalls = %#v, want none", goLoader.attachCalls)
	}
}

func TestDaemonIgnoresUnmatchedExec(t *testing.T) {
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	procLoader := &stubProcessEventLoader{
		ch: make(chan ebpf.ProcessEvent, 1),
	}
	sslLoader := &stubOpenSSLLoader{
		eventCh: make(chan ebpf.OpenSSLEvent, 1),
	}
	procLoader.ch <- ebpf.ProcessEvent{PID: 303, EventType: ebpf.ProcessEventTypeExec, TimestampNS: uint64(now.UnixNano())}
	sslLoader.eventCh <- ebpf.OpenSSLEvent{
		PID:        303,
		SessionPtr: 0x3,
		ProbeKind:  ebpf.OpenSSLProbeKindSSLConnect,
		EventType:  ebpf.OpenSSLEventTypeHandshake,
		Value:      1,
	}
	close(procLoader.ch)
	close(sslLoader.eventCh)
	var stdout bytes.Buffer
	cfg, err := NewConfig("curl", false, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	d := &Daemon{
		Config:        cfg,
		ProcessEvents: procLoader,
		OpenSSL:       sslLoader,
		Monitor: NewProcessMonitor("curl", staticExeResolver{
			paths: map[int]string{303: "/usr/bin/wget"},
		}),
		OpenSSLLibraryFinder: func() ([]string, error) { return nil, nil },
		Now:                  func() time.Time { return now },
		Stdout:               &stdout,
	}

	if err := d.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestDaemonUnsupportedRuntimePrintsSingleSummary(t *testing.T) {
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	var stdout bytes.Buffer
	cfg, err := NewConfig("curl", false, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	d := &Daemon{
		Config:  cfg,
		OpenSSL: &stubOpenSSLLoader{attachedPaths: []string{"/usr/lib/libssl.so.3"}},
		Monitor: NewProcessMonitor("curl", staticExeResolver{
			paths: map[int]string{505: "/usr/bin/curl"},
		}),
		Now:       func() time.Time { return now },
		Stdout:    &stdout,
		Artifacts: NewArtifactWriter(cfg.CacheRoot),
		Store:     NewSessionStore(),
	}
	match := ProcessMatch{PID: 505, ExePath: "/usr/bin/curl", Basename: "curl"}

	d.emitUnsupportedRuntime(505, match)

	if got, want := strings.Count(stdout.String(), "session pid-505-ssl-0x0"), 1; got != want {
		t.Fatalf("session header count = %d, want %d (%q)", got, want, stdout.String())
	}
	if !strings.Contains(stdout.String(), "pid=505") {
		t.Fatalf("stdout = %q, want pid", stdout.String())
	}
}

type stubProcessEventLoader struct {
	ch chan ebpf.ProcessEvent
}

func (s *stubProcessEventLoader) ReadProcessEvent() (ebpf.ProcessEvent, error) {
	event, ok := <-s.ch
	if !ok {
		return ebpf.ProcessEvent{}, ringbuf.ErrClosed
	}
	return event, nil
}

func (s *stubProcessEventLoader) Close() error { return nil }

type stubOpenSSLLoader struct {
	attachedPaths []string
	eventCh       chan ebpf.OpenSSLEvent
	appDataCh     chan ebpf.OpenSSLAppDataEvent
}

type stubGnuTLSLoader struct {
	attachedPaths []string
	eventCh       chan ebpf.GnuTLSEvent
	appDataCh     chan ebpf.GnuTLSAppDataEvent
}

type goAttachCall struct {
	pid            int
	executablePath string
}

type stubGoTLSLoader struct {
	attachCalls []goAttachCall
	eventCh     chan ebpf.GoTLSEvent
	appDataCh   chan ebpf.GoTLSAppDataEvent
}

type stubGoTLSInspector struct {
	inspection GoTLSInspection
	ok         bool
	err        error
}

type stubInspector struct {
	inspection OpenSSLInspection
	err        error
}

func (s stubInspector) Inspect(pid int, sslPtr uint64) (OpenSSLInspection, error) {
	return s.inspection, s.err
}

type inspectionResult struct {
	inspection OpenSSLInspection
	err        error
}

type sequenceInspector struct {
	results []inspectionResult
	calls   int
}

func (s *sequenceInspector) Inspect(pid int, sslPtr uint64) (OpenSSLInspection, error) {
	if s.calls >= len(s.results) {
		s.calls++
		return OpenSSLInspection{}, nil
	}
	result := s.results[s.calls]
	s.calls++
	return result.inspection, result.err
}

func (s *stubOpenSSLLoader) AttachedLibraryPaths() []string {
	return append([]string(nil), s.attachedPaths...)
}

func (s *stubOpenSSLLoader) AttachLibraryPath(path string) error {
	s.attachedPaths = append(s.attachedPaths, path)
	return nil
}

func (s *stubOpenSSLLoader) ReadOpenSSLEvent() (ebpf.OpenSSLEvent, error) {
	event, ok := <-s.eventCh
	if !ok {
		return ebpf.OpenSSLEvent{}, ringbuf.ErrClosed
	}
	return event, nil
}

func (s *stubOpenSSLLoader) ReadOpenSSLAppDataEvent() (ebpf.OpenSSLAppDataEvent, error) {
	event, ok := <-s.appDataCh
	if !ok {
		return ebpf.OpenSSLAppDataEvent{}, ringbuf.ErrClosed
	}
	return event, nil
}

func (s *stubOpenSSLLoader) Close() error { return nil }

func (s *stubGnuTLSLoader) AttachedLibraryPaths() []string {
	return append([]string(nil), s.attachedPaths...)
}

func (s *stubGnuTLSLoader) AttachLibraryPath(path string) error {
	s.attachedPaths = append(s.attachedPaths, path)
	return nil
}

func (s *stubGnuTLSLoader) ReadGnuTLSEvent() (ebpf.GnuTLSEvent, error) {
	event, ok := <-s.eventCh
	if !ok {
		return ebpf.GnuTLSEvent{}, ringbuf.ErrClosed
	}
	return event, nil
}

func (s *stubGnuTLSLoader) ReadGnuTLSAppDataEvent() (ebpf.GnuTLSAppDataEvent, error) {
	event, ok := <-s.appDataCh
	if !ok {
		return ebpf.GnuTLSAppDataEvent{}, ringbuf.ErrClosed
	}
	return event, nil
}

func (s *stubGnuTLSLoader) Close() error { return nil }

func (s *stubGoTLSLoader) AttachProcess(pid int, executablePath string) error {
	s.attachCalls = append(s.attachCalls, goAttachCall{pid: pid, executablePath: executablePath})
	return nil
}

func (s *stubGoTLSLoader) ReadGoTLSEvent() (ebpf.GoTLSEvent, error) {
	if s.eventCh == nil {
		return ebpf.GoTLSEvent{}, ringbuf.ErrClosed
	}
	event, ok := <-s.eventCh
	if !ok {
		return ebpf.GoTLSEvent{}, ringbuf.ErrClosed
	}
	return event, nil
}

func (s *stubGoTLSLoader) ReadGoTLSAppDataEvent() (ebpf.GoTLSAppDataEvent, error) {
	if s.appDataCh == nil {
		return ebpf.GoTLSAppDataEvent{}, ringbuf.ErrClosed
	}
	event, ok := <-s.appDataCh
	if !ok {
		return ebpf.GoTLSAppDataEvent{}, ringbuf.ErrClosed
	}
	return event, nil
}

func (s *stubGoTLSLoader) Close() error { return nil }

func (s stubGoTLSInspector) Inspect(pid int, connPtr uint64, probeKind ebpf.GoTLSProbeKind) (GoTLSInspection, bool, error) {
	return s.inspection, s.ok, s.err
}

func newAppDataEvent(pid uint32, sessionPtr uint64, direction ebpf.OpenSSLAppDataDirection, data []byte) ebpf.OpenSSLAppDataEvent {
	var payload [512]byte
	copy(payload[:], data)
	return ebpf.OpenSSLAppDataEvent{
		PID:           pid,
		SessionPtr:    sessionPtr,
		Direction:     direction,
		DataLen:       uint32(len(data)),
		PayloadLength: uint32(len(data)),
		Payload:       payload,
	}
}

func newGnuTLSAppDataEvent(pid uint32, sessionPtr uint64, direction ebpf.GnuTLSAppDataDirection, data []byte) ebpf.GnuTLSAppDataEvent {
	var payload [512]byte
	copy(payload[:], data)
	return ebpf.GnuTLSAppDataEvent{
		PID:           pid,
		SessionPtr:    sessionPtr,
		Direction:     direction,
		DataLen:       uint32(len(data)),
		PayloadLength: uint32(len(data)),
		Payload:       payload,
	}
}

func newGoTLSAppDataEvent(pid uint32, connPtr uint64, direction ebpf.GoTLSAppDataDirection, data []byte) ebpf.GoTLSAppDataEvent {
	var payload [512]byte
	copy(payload[:], data)
	return ebpf.GoTLSAppDataEvent{
		PID:           pid,
		ConnPtr:       connPtr,
		Direction:     direction,
		PayloadLength: uint32(len(data)),
		Payload:       payload,
	}
}

func TestDaemonMergesGoTLSMetadata(t *testing.T) {
	now := time.Date(2026, 5, 10, 14, 0, 0, 0, time.UTC)
	var stdout bytes.Buffer
	cfg, err := NewConfig("go-client", true, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	d := &Daemon{
		Config: cfg,
		GoTLS:  &stubGoTLSLoader{},
		GoInspector: stubGoTLSInspector{
			ok: true,
			inspection: GoTLSInspection{
				Role:        "client",
				SNI:         "example.com",
				TLSVersion:  "TLS 1.3",
				CipherSuite: "TLS_AES_128_GCM_SHA256",
				ALPN:        "h2",
				KeyStatus:   KeyStatusUnavailable,
			},
		},
		Monitor: NewProcessMonitor("go-client", staticExeResolver{
			paths: map[int]string{1001: "/tmp/go-client"},
		}),
		Now:       func() time.Time { return now },
		Stdout:    &stdout,
		Artifacts: NewArtifactWriter(cfg.CacheRoot),
		Store:     NewSessionStore(),
	}
	tracked := map[int]ProcessMatch{
		1001: {PID: 1001, ExePath: "/tmp/go-client", Basename: "go-client"},
	}
	seen := map[int]bool{1001: false}
	fds := make(map[SessionKey]int)
	exited := map[int]time.Time{1001: now.Add(time.Second)}

	d.handleGoTLSEvent(ebpf.GoTLSEvent{
		PID:         1001,
		TimestampNS: uint64(now.UnixNano()),
		ConnPtr:     0x9,
		ProbeKind:   ebpf.GoTLSProbeKindConnectionState,
	}, tracked, seen, fds)
	d.flushExited(tracked, seen, fds, exited, time.Unix(1<<62, 0))

	for _, want := range []string{
		"tls=TLS 1.3",
		"cipher=TLS_AES_128_GCM_SHA256",
		"alpn=h2",
		"sni=example.com",
		`note="go key export not implemented; plaintext capture not implemented"`,
		"key_status=unavailable",
		"capture=capture",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}

	summaryPath := filepath.Join(cfg.CacheRoot, "pid-1001-ssl-0x9", "summary.json")
	rawSummary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("ReadFile(summary.json) error = %v", err)
	}

	var summary struct {
		Metadata SessionMetadata `json:"metadata"`
	}
	if err := json.Unmarshal(rawSummary, &summary); err != nil {
		t.Fatalf("Unmarshal(summary.json) error = %v", err)
	}
	if got, want := summary.Metadata.Role, "client"; got != want {
		t.Fatalf("Role = %q, want %q", got, want)
	}
	if got, want := summary.Metadata.TLSVersion, "TLS 1.3"; got != want {
		t.Fatalf("TLSVersion = %q, want %q", got, want)
	}
	if got, want := summary.Metadata.CipherSuite, "TLS_AES_128_GCM_SHA256"; got != want {
		t.Fatalf("CipherSuite = %q, want %q", got, want)
	}
	if got, want := summary.Metadata.ALPN, "h2"; got != want {
		t.Fatalf("ALPN = %q, want %q", got, want)
	}
	if got, want := summary.Metadata.KeyStatus, KeyStatusUnavailable; got != want {
		t.Fatalf("KeyStatus = %q, want %q", got, want)
	}
	if got, want := summary.Metadata.KeyStatusNote, "go key export not implemented; plaintext capture not implemented"; got != want {
		t.Fatalf("KeyStatusNote = %q, want %q", got, want)
	}
}

func TestDaemonCapturesGoTLSPlaintextStreams(t *testing.T) {
	now := time.Date(2026, 5, 10, 15, 0, 0, 0, time.UTC)
	var stdout bytes.Buffer
	cfg, err := NewConfig("go-client", true, t.TempDir())
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	d := &Daemon{
		Config: cfg,
		GoTLS:  &stubGoTLSLoader{},
		GoInspector: stubGoTLSInspector{
			ok: true,
			inspection: GoTLSInspection{
				Role:        "client",
				SNI:         "example.com",
				TLSVersion:  "TLS 1.3",
				CipherSuite: "TLS_AES_128_GCM_SHA256",
				ALPN:        "http/1.1",
				KeyStatus:   KeyStatusUnavailable,
			},
		},
		Monitor: NewProcessMonitor("go-client", staticExeResolver{
			paths: map[int]string{1002: "/tmp/go-client"},
		}),
		Now:       func() time.Time { return now },
		Stdout:    &stdout,
		Artifacts: NewArtifactWriter(cfg.CacheRoot),
		Store:     NewSessionStore(),
	}
	tracked := map[int]ProcessMatch{
		1002: {PID: 1002, ExePath: "/tmp/go-client", Basename: "go-client"},
	}
	seen := map[int]bool{1002: false}
	fds := make(map[SessionKey]int)
	exited := map[int]time.Time{1002: now.Add(time.Second)}

	d.handleGoTLSEvent(ebpf.GoTLSEvent{
		PID:         1002,
		TimestampNS: uint64(now.UnixNano()),
		ConnPtr:     0xa,
		ProbeKind:   ebpf.GoTLSProbeKindConnectionState,
	}, tracked, seen, fds)
	d.handleGoTLSAppDataEvent(newGoTLSAppDataEvent(1002, 0xa, ebpf.GoTLSAppDataDirectionWrite, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")), tracked)
	d.handleGoTLSAppDataEvent(newGoTLSAppDataEvent(1002, 0xa, ebpf.GoTLSAppDataDirectionRead, []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")), tracked)
	d.flushExited(tracked, seen, fds, exited, time.Unix(1<<62, 0))

	if !strings.Contains(stdout.String(), "GET / HTTP/1.1") || !strings.Contains(stdout.String(), "HTTP/1.1 200 OK") {
		t.Fatalf("stdout = %q, want capture output", stdout.String())
	}

	requestPath := filepath.Join(cfg.CacheRoot, "pid-1002-ssl-0xa", "request.txt")
	request, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatalf("ReadFile(request.txt) error = %v", err)
	}
	if !strings.Contains(string(request), "GET / HTTP/1.1") {
		t.Fatalf("request.txt = %q, want HTTP request", request)
	}

	responsePath := filepath.Join(cfg.CacheRoot, "pid-1002-ssl-0xa", "response.txt")
	response, err := os.ReadFile(responsePath)
	if err != nil {
		t.Fatalf("ReadFile(response.txt) error = %v", err)
	}
	if !strings.Contains(string(response), "HTTP/1.1 200 OK") || !strings.Contains(string(response), "hello") {
		t.Fatalf("response.txt = %q, want HTTP response", response)
	}
}

func toSNIBytes(s string) [64]byte {
	var out [64]byte
	copy(out[:], []byte(s))
	return out
}
