package fcktls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/moolen/FCKTLS/pkg/ebpf"
)

type processEventReader interface {
	ReadProcessEvent() (ebpf.ProcessEvent, error)
	Close() error
}

type openSSLReader interface {
	AttachLibraryPath(string) error
	ReadOpenSSLEvent() (ebpf.OpenSSLEvent, error)
	ReadOpenSSLAppDataEvent() (ebpf.OpenSSLAppDataEvent, error)
	Close() error
}

type Daemon struct {
	Config        Config
	ProcessEvents processEventReader
	OpenSSL       openSSLReader
	Inspector     OpenSSLInspector
	Monitor       ProcessMonitor
	LibraryFinder func() ([]string, error)
	Now           func() time.Time
	Stdout        io.Writer
	Artifacts     ArtifactWriter
	Store         *SessionStore

	inspectedSessions map[SessionKey]bool
}

func NewDaemon(cfg Config) (*Daemon, error) {
	processEvents, err := ebpf.NewProcessEventLoader()
	if err != nil {
		return nil, err
	}
	openssl, err := ebpf.NewOpenSSLLoader()
	if err != nil {
		_ = processEvents.Close()
		return nil, err
	}

	return &Daemon{
		Config:        cfg,
		ProcessEvents: processEvents,
		OpenSSL:       openssl,
		Inspector:     newDefaultOpenSSLInspector(),
		Monitor:       NewProcessMonitor(cfg.Target, nil),
		LibraryFinder: discoverOpenSSLLibraries,
		Now:           time.Now,
		Stdout:        os.Stdout,
		Artifacts:     NewArtifactWriter(cfg.CacheRoot),
		Store:         NewSessionStore(),
	}, nil
}

func (d *Daemon) Run(ctx context.Context) error {
	if d == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Stdout == nil {
		d.Stdout = io.Discard
	}
	if d.Store == nil {
		d.Store = NewSessionStore()
	}
	if d.inspectedSessions == nil {
		d.inspectedSessions = make(map[SessionKey]bool)
	}
	if d.Artifacts.CacheRoot == "" {
		d.Artifacts = NewArtifactWriter(d.Config.CacheRoot)
	}
	if d.LibraryFinder == nil {
		d.LibraryFinder = discoverOpenSSLLibraries
	}
	if d.ProcessEvents == nil || d.OpenSSL == nil {
		return errors.New("daemon readers must be configured")
	}

	defer d.ProcessEvents.Close()
	defer d.OpenSSL.Close()

	if err := d.attachLibraries(); err != nil {
		return err
	}

	tracked := make(map[int]ProcessMatch)
	seenOpenSSL := make(map[int]bool)
	fdBySession := make(map[SessionKey]int)
	exited := make(map[int]time.Time)

	procCh := make(chan ebpf.ProcessEvent, 32)
	sslCh := make(chan ebpf.OpenSSLEvent, 64)
	appCh := make(chan ebpf.OpenSSLAppDataEvent, 64)
	errCh := make(chan error, 3)

	go func() {
		<-ctx.Done()
		_ = d.ProcessEvents.Close()
		_ = d.OpenSSL.Close()
	}()

	go pumpProcessEvents(d.ProcessEvents, procCh, errCh)
	go pumpOpenSSLEvents(d.OpenSSL, sslCh, errCh)
	if d.Config.CaptureMode == CaptureModeCapture {
		go pumpOpenSSLAppDataEvents(d.OpenSSL, appCh, errCh)
	} else {
		close(appCh)
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for procCh != nil || sslCh != nil || appCh != nil {
		select {
		case <-ctx.Done():
			for pid, match := range tracked {
				d.emitUnsupportedRuntime(pid, match)
			}
			return nil
		case err := <-errCh:
			if err != nil {
				return err
			}
		case <-ticker.C:
			_ = d.attachLibraries()
			d.flushExited(tracked, seenOpenSSL, fdBySession, exited, d.Now().Add(-100*time.Millisecond))
		case event, ok := <-procCh:
			if !ok {
				procCh = nil
				continue
			}
			d.handleProcessEvent(event, tracked, seenOpenSSL, fdBySession, exited)
		case event, ok := <-sslCh:
			if !ok {
				sslCh = nil
				continue
			}
			d.handleOpenSSLEvent(event, tracked, seenOpenSSL, fdBySession)
		case event, ok := <-appCh:
			if !ok {
				appCh = nil
				continue
			}
			d.handleAppDataEvent(event, tracked)
		}
	}

	d.flushExited(tracked, seenOpenSSL, fdBySession, exited, time.Unix(1<<62, 0))

	return nil
}

func (d *Daemon) attachLibraries() error {
	paths, err := d.LibraryFinder()
	if err != nil {
		return fmt.Errorf("discover openssl libraries: %w", err)
	}
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		if err := d.OpenSSL.AttachLibraryPath(path); err != nil {
			return err
		}
	}
	return nil
}

func (d *Daemon) handleProcessEvent(event ebpf.ProcessEvent, tracked map[int]ProcessMatch, seenOpenSSL map[int]bool, fdBySession map[SessionKey]int, exited map[int]time.Time) {
	pid := int(event.PID)
	switch event.EventType {
	case ebpf.ProcessEventTypeExec:
		match, ok, err := d.Monitor.MatchPID(pid)
		if err != nil || !ok {
			return
		}
		tracked[pid] = match
		seenOpenSSL[pid] = false
		delete(exited, pid)
	case ebpf.ProcessEventTypeExit:
		exited[pid] = time.Unix(0, int64(event.TimestampNS))
	}
}

func (d *Daemon) handleOpenSSLEvent(event ebpf.OpenSSLEvent, tracked map[int]ProcessMatch, seenOpenSSL map[int]bool, fdBySession map[SessionKey]int) {
	match, ok := tracked[int(event.PID)]
	if !ok || event.SessionPtr == 0 {
		return
	}
	if d.inspectedSessions == nil {
		d.inspectedSessions = make(map[SessionKey]bool)
	}
	seenOpenSSL[int(event.PID)] = true
	key := SessionKey{PID: int(event.PID), SSLPointer: event.SessionPtr}
	update := SessionMetadataUpdate{
		Key:         key,
		ObservedAt:  time.Unix(0, int64(event.TimestampNS)),
		PID:         int(event.PID),
		ExePath:     match.ExePath,
		LibraryPath: firstAttachedLibraryPath(d.OpenSSL),
		Role:        roleFromProbeKind(event.ProbeKind),
		CaptureMode: d.Config.CaptureMode,
	}

	switch event.EventType {
	case ebpf.OpenSSLEventTypeSetSNI:
		update.SNI = event.StringPayload()
	case ebpf.OpenSSLEventTypeSetFD:
		fd := int(event.Value)
		update.SocketFD = &fd
		fdBySession[key] = int(event.Value)
		if local, peer, ok, err := resolveSocketTuple(int(event.PID), int(event.Value)); err == nil && ok {
			update.Source = &local
			update.Destination = &peer
		}
	case ebpf.OpenSSLEventTypeSetGroups:
		update.Groups = event.StringPayload()
	case ebpf.OpenSSLEventTypeSetVerify:
		verifyMode := int(event.Value)
		update.VerifyMode = &verifyMode
	case ebpf.OpenSSLEventTypeSessionReused:
		reused := event.Value > 0
		update.SessionReused = &reused
	case ebpf.OpenSSLEventTypeVerifyResult:
		verifyResult := int(event.Value)
		update.VerifyResult = &verifyResult
	case ebpf.OpenSSLEventTypeNegotiatedGroup:
		negotiatedGroup := int(event.Value)
		update.NegotiatedGroup = &negotiatedGroup
	case ebpf.OpenSSLEventTypeHandshake:
		if event.Value > 0 {
			if d.Inspector == nil {
				update.KeyStatus = KeyStatusUnavailable
				update.KeyStatusNote = "key export not implemented"
			}
		} else {
			update.KeyStatus = KeyStatusPartial
			update.KeyStatusNote = "handshake incomplete"
		}
	}

	snapshot := d.Store.MergeMetadata(update)
	if event.EventType == ebpf.OpenSSLEventTypeHandshake && event.Value > 0 && !d.inspectedSessions[key] && d.Inspector != nil {
		d.inspectedSessions[key] = true
		inspection, err := d.Inspector.Inspect(int(event.PID), event.SessionPtr)
		if err != nil {
			d.Store.MergeMetadata(SessionMetadataUpdate{
				Key:           key,
				ObservedAt:    time.Unix(0, int64(event.TimestampNS)),
				KeyStatus:     KeyStatusUnavailable,
				KeyStatusNote: fmt.Sprintf("openssl inspection failed: %v", err),
			})
		} else {
			d.Store.MergeMetadata(SessionMetadataUpdate{
				Key:           key,
				ObservedAt:    time.Unix(0, int64(event.TimestampNS)),
				TLSVersion:    inspection.TLSVersion,
				CipherSuite:   inspection.CipherSuite,
				ALPN:          inspection.ALPN,
				Certificates:  inspection.Certificates,
				KeyStatus:     inspection.KeyStatus,
				KeyStatusNote: inspection.KeyStatusNote,
				KeyLogLines:   inspection.KeyLogLines,
			})
		}
	}
	_ = snapshot
}

func (d *Daemon) handleAppDataEvent(event ebpf.OpenSSLAppDataEvent, tracked map[int]ProcessMatch) {
	if _, ok := tracked[int(event.PID)]; !ok || event.SessionPtr == 0 {
		return
	}

	direction := StreamDirectionClientToServer
	if event.Direction == ebpf.OpenSSLAppDataDirectionRead {
		direction = StreamDirectionServerToClient
	}
	if event.PayloadLength > uint32(len(event.Payload)) {
		return
	}
	snapshot := d.Store.AppendChunk(PlaintextChunk{
		Key:        SessionKey{PID: int(event.PID), SSLPointer: event.SessionPtr},
		Direction:  direction,
		ObservedAt: time.Unix(0, int64(event.TimestampNS)),
		Data:       append([]byte(nil), event.Payload[:event.PayloadLength]...),
	})
	_ = snapshot
}

func (d *Daemon) flushSnapshot(snapshot SessionSnapshot) {
	d.writeLine(RenderSessionSummary(snapshot))
	if snapshot.Metadata.CaptureMode == CaptureModeCapture {
		formatted := RenderCapture(snapshot)
		if strings.TrimSpace(formatted) != "no plaintext captured" {
			d.writeLine(formatted)
		}
	}
	if _, err := d.Artifacts.WriteSession(snapshot); err != nil {
		d.writeLine(fmt.Sprintf("artifact write error: %v", err))
	}
}

func (d *Daemon) emitUnsupportedRuntime(pid int, match ProcessMatch) {
	snapshot := d.Store.MergeMetadata(SessionMetadataUpdate{
		Key:           SessionKey{PID: pid, SSLPointer: 0},
		ObservedAt:    d.Now(),
		PID:           pid,
		ExePath:       match.ExePath,
		KeyStatus:     KeyStatusUnknown,
		KeyStatusNote: "matched process exited without OpenSSL events; unsupported runtime or no TLS activity",
		CaptureMode:   d.Config.CaptureMode,
	})
	d.writeLine(RenderSessionSummary(snapshot))
	if finalized, ok := d.Store.Finalize(SessionKey{PID: pid, SSLPointer: 0}, d.Now()); ok {
		d.flushSnapshot(finalized)
	}
}

func (d *Daemon) flushExited(
	tracked map[int]ProcessMatch,
	seenOpenSSL map[int]bool,
	fdBySession map[SessionKey]int,
	exited map[int]time.Time,
	cutoff time.Time,
) {
	for pid, exitedAt := range exited {
		if exitedAt.After(cutoff) {
			continue
		}
		snapshots := d.Store.FinalizeByPID(pid, exitedAt)
		if len(snapshots) == 0 && tracked[pid].PID != 0 && !seenOpenSSL[pid] {
			d.emitUnsupportedRuntime(pid, tracked[pid])
		}
		for _, snapshot := range snapshots {
			d.flushSnapshot(snapshot)
		}
		delete(tracked, pid)
		delete(seenOpenSSL, pid)
		delete(exited, pid)
		for key := range fdBySession {
			if key.PID == pid {
				delete(fdBySession, key)
			}
		}
		for key := range d.inspectedSessions {
			if key.PID == pid {
				delete(d.inspectedSessions, key)
			}
		}
	}
}

func (d *Daemon) writeLine(line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	_, _ = io.WriteString(d.Stdout, line)
}

func roleFromProbeKind(kind ebpf.OpenSSLProbeKind) string {
	switch kind {
	case ebpf.OpenSSLProbeKindSSLConnect:
		return "client"
	case ebpf.OpenSSLProbeKindSSLAccept:
		return "server"
	default:
		return "unknown"
	}
}

func firstAttachedLibraryPath(loader openSSLReader) string {
	type attachmentGetter interface {
		AttachedLibraryPaths() []string
	}
	if getter, ok := loader.(attachmentGetter); ok {
		paths := getter.AttachedLibraryPaths()
		if len(paths) > 0 {
			return paths[0]
		}
	}
	return ""
}

func discoverOpenSSLLibraries() ([]string, error) {
	candidates := []string{
		"/usr/lib",
		"/usr/lib64",
		"/usr/lib/x86_64-linux-gnu",
		"/lib",
		"/lib64",
		"/lib/x86_64-linux-gnu",
	}

	seen := make(map[string]struct{})
	var out []string
	for _, root := range candidates {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if !strings.HasPrefix(info.Name(), "libssl.so") {
				return nil
			}
			if _, ok := seen[path]; ok {
				return nil
			}
			seen[path] = struct{}{}
			out = append(out, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func pumpProcessEvents(reader processEventReader, out chan<- ebpf.ProcessEvent, errCh chan<- error) {
	defer close(out)
	for {
		event, err := reader.ReadProcessEvent()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrClosed) {
				errCh <- fmt.Errorf("read process event: %w", err)
			}
			return
		}
		out <- event
	}
}

func pumpOpenSSLEvents(reader openSSLReader, out chan<- ebpf.OpenSSLEvent, errCh chan<- error) {
	defer close(out)
	for {
		event, err := reader.ReadOpenSSLEvent()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrClosed) {
				errCh <- fmt.Errorf("read openssl event: %w", err)
			}
			return
		}
		out <- event
	}
}

func pumpOpenSSLAppDataEvents(reader openSSLReader, out chan<- ebpf.OpenSSLAppDataEvent, errCh chan<- error) {
	defer close(out)
	for {
		event, err := reader.ReadOpenSSLAppDataEvent()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrClosed) {
				errCh <- fmt.Errorf("read openssl app data event: %w", err)
			}
			return
		}
		out <- event
	}
}
