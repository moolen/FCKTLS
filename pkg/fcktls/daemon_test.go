package fcktls

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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
		EventType:  ebpf.OpenSSLEventTypeSetSNI,
		SNIBytes:   toSNIBytes("example.com"),
	}, tracked, seen, fds)
	d.handleOpenSSLEvent(ebpf.OpenSSLEvent{
		PID:        101,
		SessionPtr: 0x1,
		ProbeKind:  ebpf.OpenSSLProbeKindSSLConnect,
		EventType:  ebpf.OpenSSLEventTypeHandshake,
		Value:      1,
	}, tracked, seen, fds)
	d.flushExited(tracked, seen, fds, exited, time.Unix(1<<62, 0))

	if !strings.Contains(stdout.String(), "example.com") {
		t.Fatalf("stdout = %q, want SNI", stdout.String())
	}
	summaryPath := filepath.Join(cfg.CacheRoot, "pid-101-ssl-0x1", "summary.json")
	if _, err := os.Stat(summaryPath); err != nil {
		t.Fatalf("summary.json stat error = %v", err)
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
		LibraryFinder: func() ([]string, error) { return nil, nil },
		Now:           func() time.Time { return now },
		Stdout:        &stdout,
	}

	if err := d.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
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

func toSNIBytes(s string) [64]byte {
	var out [64]byte
	copy(out[:], []byte(s))
	return out
}
