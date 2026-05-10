package fcktls

import (
	"context"
	"encoding/hex"
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

type gnuTLSReader interface {
	AttachLibraryPath(string) error
	ReadGnuTLSEvent() (ebpf.GnuTLSEvent, error)
	ReadGnuTLSAppDataEvent() (ebpf.GnuTLSAppDataEvent, error)
	Close() error
}

type goTLSReader interface {
	AttachProcess(pid int, executablePath string) error
	ReadGoTLSEvent() (ebpf.GoTLSEvent, error)
	Close() error
}

type Daemon struct {
	Config               Config
	ProcessEvents        processEventReader
	OpenSSL              openSSLReader
	GnuTLS               gnuTLSReader
	GoTLS                goTLSReader
	GoExecGate           *GoExecGate
	GoInspector          GoTLSInspector
	Inspector            OpenSSLInspector
	Monitor              ProcessMonitor
	OpenSSLLibraryFinder func() ([]string, error)
	GnuTLSLibraryFinder  func() ([]string, error)
	Now                  func() time.Time
	Stdout               io.Writer
	Artifacts            ArtifactWriter
	Store                *SessionStore
	OnReady              func()

	inspectedSessions map[SessionKey]bool
	inspectAttempts   map[SessionKey]int
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
	gnutls, err := ebpf.NewGnuTLSLoader()
	if err != nil {
		_ = openssl.Close()
		_ = processEvents.Close()
		return nil, err
	}
	goTLS, err := ebpf.NewGoTLSLoader()
	if err != nil {
		_ = gnutls.Close()
		_ = openssl.Close()
		_ = processEvents.Close()
		return nil, err
	}

	daemon := &Daemon{
		Config:               cfg,
		ProcessEvents:        processEvents,
		OpenSSL:              openssl,
		GnuTLS:               gnutls,
		GoTLS:                goTLS,
		Inspector:            newDefaultOpenSSLInspector(),
		GoInspector:          newDefaultGoTLSInspector(),
		Monitor:              NewProcessMonitor(cfg.Target, nil),
		OpenSSLLibraryFinder: discoverOpenSSLLibraries,
		GnuTLSLibraryFinder:  discoverGnuTLSLibraries,
		Now:                  time.Now,
		Stdout:               os.Stdout,
		Artifacts:            NewArtifactWriter(cfg.CacheRoot),
		Store:                NewSessionStore(),
	}
	daemon.GoExecGate = NewGoExecGate(goTLS)
	return daemon, nil
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
	if d.inspectAttempts == nil {
		d.inspectAttempts = make(map[SessionKey]int)
	}
	if d.Artifacts.CacheRoot == "" {
		d.Artifacts = NewArtifactWriter(d.Config.CacheRoot)
	}
	if d.OpenSSLLibraryFinder == nil {
		d.OpenSSLLibraryFinder = discoverOpenSSLLibraries
	}
	if d.GnuTLSLibraryFinder == nil {
		d.GnuTLSLibraryFinder = discoverGnuTLSLibraries
	}
	if d.ProcessEvents == nil || d.OpenSSL == nil {
		return errors.New("daemon readers must be configured")
	}

	defer d.ProcessEvents.Close()
	defer d.OpenSSL.Close()
	if d.GnuTLS != nil {
		defer d.GnuTLS.Close()
	}
	if d.GoTLS != nil {
		defer d.GoTLS.Close()
	}

	if err := d.attachLibraries(); err != nil {
		return err
	}

	tracked := make(map[int]ProcessMatch)
	seenTLS := make(map[int]bool)
	fdBySession := make(map[SessionKey]int)
	exited := make(map[int]time.Time)

	procCh := make(chan ebpf.ProcessEvent, 32)
	sslCh := make(chan ebpf.OpenSSLEvent, 64)
	appCh := make(chan ebpf.OpenSSLAppDataEvent, 64)
	gnutlsCh := make(chan ebpf.GnuTLSEvent, 64)
	gnutlsAppCh := make(chan ebpf.GnuTLSAppDataEvent, 64)
	goTLSCh := make(chan ebpf.GoTLSEvent, 64)
	errCh := make(chan error, 6)

	go func() {
		<-ctx.Done()
		_ = d.ProcessEvents.Close()
		_ = d.OpenSSL.Close()
		if d.GnuTLS != nil {
			_ = d.GnuTLS.Close()
		}
		if d.GoTLS != nil {
			_ = d.GoTLS.Close()
		}
	}()

	go pumpProcessEvents(d.ProcessEvents, procCh, errCh)
	go pumpOpenSSLEvents(d.OpenSSL, sslCh, errCh)
	if d.GnuTLS != nil {
		go pumpGnuTLSEvents(d.GnuTLS, gnutlsCh, errCh)
	} else {
		close(gnutlsCh)
	}
	if d.GoTLS != nil {
		go pumpGoTLSEvents(d.GoTLS, goTLSCh, errCh)
	} else {
		close(goTLSCh)
	}
	if d.Config.CaptureMode == CaptureModeCapture {
		go pumpOpenSSLAppDataEvents(d.OpenSSL, appCh, errCh)
		if d.GnuTLS != nil {
			go pumpGnuTLSAppDataEvents(d.GnuTLS, gnutlsAppCh, errCh)
		} else {
			close(gnutlsAppCh)
		}
	} else {
		close(appCh)
		close(gnutlsAppCh)
	}
	if d.OnReady != nil {
		d.OnReady()
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for procCh != nil || sslCh != nil || appCh != nil || gnutlsCh != nil || gnutlsAppCh != nil || goTLSCh != nil {
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
			d.flushExited(tracked, seenTLS, fdBySession, exited, d.Now().Add(-100*time.Millisecond))
		case event, ok := <-procCh:
			if !ok {
				procCh = nil
				continue
			}
			d.handleProcessEvent(event, tracked, seenTLS, fdBySession, exited)
		case event, ok := <-sslCh:
			if !ok {
				sslCh = nil
				continue
			}
			d.handleOpenSSLEvent(event, tracked, seenTLS, fdBySession)
		case event, ok := <-appCh:
			if !ok {
				appCh = nil
				continue
			}
			d.handleAppDataEvent(event, tracked)
		case event, ok := <-gnutlsCh:
			if !ok {
				gnutlsCh = nil
				continue
			}
			d.handleGnuTLSEvent(event, tracked, seenTLS, fdBySession)
		case event, ok := <-gnutlsAppCh:
			if !ok {
				gnutlsAppCh = nil
				continue
			}
			d.handleGnuTLSAppDataEvent(event, tracked)
		case event, ok := <-goTLSCh:
			if !ok {
				goTLSCh = nil
				continue
			}
			d.handleGoTLSEvent(event, tracked, seenTLS, fdBySession)
		}
	}

	d.flushExited(tracked, seenTLS, fdBySession, exited, time.Unix(1<<62, 0))

	return nil
}

func (d *Daemon) attachLibraries() error {
	if err := attachLibrarySet(d.OpenSSL, d.OpenSSLLibraryFinder, "openssl"); err != nil {
		return err
	}
	if d.GnuTLS != nil {
		if err := attachLibrarySet(d.GnuTLS, d.GnuTLSLibraryFinder, "gnutls"); err != nil {
			return err
		}
	}
	return nil
}

func (d *Daemon) handleProcessEvent(event ebpf.ProcessEvent, tracked map[int]ProcessMatch, seenTLS map[int]bool, fdBySession map[SessionKey]int, exited map[int]time.Time) {
	pid := int(event.PID)
	switch event.EventType {
	case ebpf.ProcessEventTypeExec:
		match, ok, err := d.Monitor.MatchPID(pid)
		if err != nil || !ok {
			return
		}
		tracked[pid] = match
		seenTLS[pid] = false
		if d.shouldGateGoProcess(match) {
			attached, err := d.GoExecGate.HandleMatch(match)
			if err == nil && attached {
				seenTLS[pid] = true
			}
		}
		delete(exited, pid)
	case ebpf.ProcessEventTypeExit:
		exited[pid] = time.Unix(0, int64(event.TimestampNS))
	}
}

func (d *Daemon) shouldGateGoProcess(match ProcessMatch) bool {
	return d != nil && d.GoTLS != nil && d.GoExecGate != nil && match.PID > 0 && strings.TrimSpace(match.ExePath) != ""
}

func (d *Daemon) handleOpenSSLEvent(event ebpf.OpenSSLEvent, tracked map[int]ProcessMatch, seenTLS map[int]bool, fdBySession map[SessionKey]int) {
	match, ok := tracked[int(event.PID)]
	if !ok || event.SessionPtr == 0 {
		return
	}
	if d.inspectedSessions == nil {
		d.inspectedSessions = make(map[SessionKey]bool)
	}
	seenTLS[int(event.PID)] = true
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
	case ebpf.OpenSSLEventTypeKeyMaterial:
		if line, ok := formatOpenSSLKeyMaterialLine(event); ok {
			if isTLS13KeyLogLabel(event.StringPayload()) {
				update.TLSVersion = "TLSv1.3"
			}
			update.KeyStatus = KeyStatusAvailable
			update.KeyStatusNote = "openssl key material captured via uprobe"
			update.KeyLogLines = []string{line}
		}
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
	if d.shouldInspectOpenSSLEvent(event) {
		d.inspectOpenSSLSession(key, int(event.PID), event.SessionPtr, time.Unix(0, int64(event.TimestampNS)))
	}
	_ = snapshot
}

func (d *Daemon) handleGnuTLSEvent(event ebpf.GnuTLSEvent, tracked map[int]ProcessMatch, seenTLS map[int]bool, fdBySession map[SessionKey]int) {
	match, ok := tracked[int(event.PID)]
	if !ok || event.SessionPtr == 0 {
		return
	}

	seenTLS[int(event.PID)] = true
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
		update.Priority = event.StringPayload()
	case ebpf.GnuTLSEventTypeSetFD:
		fd := int(event.Value)
		update.SocketFD = &fd
		fdBySession[key] = fd
		if local, peer, ok, err := resolveSocketTuple(int(event.PID), fd); err == nil && ok {
			update.Source = &local
			update.Destination = &peer
		}
	case ebpf.GnuTLSEventTypeSessionResumed:
		reused := event.Value > 0
		update.SessionReused = &reused
	case ebpf.GnuTLSEventTypeVerifyStatus:
		verifyResult := int(event.Value)
		update.VerifyResult = &verifyResult
	case ebpf.GnuTLSEventTypeNegotiatedGroup:
		negotiatedGroup := int(event.Value)
		update.NegotiatedGroup = &negotiatedGroup
	case ebpf.GnuTLSEventTypeHandshake:
		if event.Value == 0 {
			update.KeyStatus = KeyStatusUnavailable
			update.KeyStatusNote = "gnutls key export not implemented"
		} else {
			update.KeyStatus = KeyStatusPartial
			update.KeyStatusNote = "gnutls handshake incomplete"
		}
	}

	_ = d.Store.MergeMetadata(update)
}

func (d *Daemon) handleGoTLSEvent(event ebpf.GoTLSEvent, tracked map[int]ProcessMatch, seenTLS map[int]bool, fdBySession map[SessionKey]int) {
	match, ok := tracked[int(event.PID)]
	if !ok || event.ConnPtr == 0 {
		return
	}

	seenTLS[int(event.PID)] = true
	key := SessionKey{PID: int(event.PID), SSLPointer: event.ConnPtr}
	update := SessionMetadataUpdate{
		Key:           key,
		ObservedAt:    time.Unix(0, int64(event.TimestampNS)),
		PID:           int(event.PID),
		ExePath:       match.ExePath,
		Role:          goTLSProbeKindRole(event.ProbeKind, true),
		CaptureMode:   d.Config.CaptureMode,
		KeyStatus:     KeyStatusUnavailable,
		KeyStatusNote: goTLSUnavailableNote(d.Config.CaptureMode, "go key export not implemented"),
	}

	if d.GoInspector != nil {
		inspection, ok, err := d.GoInspector.Inspect(int(event.PID), event.ConnPtr, event.ProbeKind)
		if err != nil {
			update.KeyStatus = KeyStatusPartial
			update.KeyStatusNote = goTLSUnavailableNote(d.Config.CaptureMode, fmt.Sprintf("go tls inspection failed: %v", err))
		} else if ok {
			if inspection.Role != "" {
				update.Role = inspection.Role
			}
			update.SNI = inspection.SNI
			update.TLSVersion = inspection.TLSVersion
			update.CipherSuite = inspection.CipherSuite
			update.ALPN = inspection.ALPN
			update.Certificates = inspection.Certificates
			if inspection.KeyStatus != "" {
				update.KeyStatus = inspection.KeyStatus
			}
			if note := strings.TrimSpace(inspection.KeyStatusNote); note != "" {
				update.KeyStatusNote = goTLSUnavailableNote(d.Config.CaptureMode, note)
			}
		}
	}

	_ = d.Store.MergeMetadata(update)
}

func (d *Daemon) handleAppDataEvent(event ebpf.OpenSSLAppDataEvent, tracked map[int]ProcessMatch) {
	if _, ok := tracked[int(event.PID)]; !ok || event.SessionPtr == 0 {
		return
	}
	d.inspectOpenSSLSession(
		SessionKey{PID: int(event.PID), SSLPointer: event.SessionPtr},
		int(event.PID),
		event.SessionPtr,
		time.Unix(0, int64(event.TimestampNS)),
	)

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

func (d *Daemon) handleGnuTLSAppDataEvent(event ebpf.GnuTLSAppDataEvent, tracked map[int]ProcessMatch) {
	if _, ok := tracked[int(event.PID)]; !ok || event.SessionPtr == 0 {
		return
	}

	direction := StreamDirectionClientToServer
	if event.Direction == ebpf.GnuTLSAppDataDirectionRead {
		direction = StreamDirectionServerToClient
	}
	if event.PayloadLength > uint32(len(event.Payload)) {
		return
	}
	_ = d.Store.AppendChunk(PlaintextChunk{
		Key:        SessionKey{PID: int(event.PID), SSLPointer: event.SessionPtr},
		Direction:  direction,
		ObservedAt: time.Unix(0, int64(event.TimestampNS)),
		Data:       append([]byte(nil), event.Payload[:event.PayloadLength]...),
	})
}

func (d *Daemon) shouldInspectOpenSSLEvent(event ebpf.OpenSSLEvent) bool {
	if d == nil || d.Inspector == nil {
		return false
	}
	switch event.EventType {
	case ebpf.OpenSSLEventTypeHandshake:
		return event.Value > 0
	case ebpf.OpenSSLEventTypeVerifyResult, ebpf.OpenSSLEventTypeSessionReused, ebpf.OpenSSLEventTypeNegotiatedGroup, ebpf.OpenSSLEventTypeKeyMaterial:
		return true
	default:
		return false
	}
}

func (d *Daemon) inspectOpenSSLSession(key SessionKey, pid int, sslPtr uint64, observedAt time.Time) {
	if d == nil || d.Inspector == nil || sslPtr == 0 {
		return
	}
	if d.inspectedSessions == nil {
		d.inspectedSessions = make(map[SessionKey]bool)
	}
	if d.inspectAttempts == nil {
		d.inspectAttempts = make(map[SessionKey]int)
	}
	if d.inspectedSessions[key] {
		return
	}
	if d.inspectAttempts[key] >= 3 {
		return
	}
	d.inspectAttempts[key]++

	inspection, err := d.Inspector.Inspect(pid, sslPtr)
	if err != nil {
		d.Store.MergeMetadata(SessionMetadataUpdate{
			Key:           key,
			ObservedAt:    observedAt,
			KeyStatus:     KeyStatusUnavailable,
			KeyStatusNote: fmt.Sprintf("openssl inspection failed: %v", err),
		})
		return
	}

	if inspectionComplete(inspection) {
		d.inspectedSessions[key] = true
	}
	d.Store.MergeMetadata(SessionMetadataUpdate{
		Key:           key,
		ObservedAt:    observedAt,
		TLSVersion:    inspection.TLSVersion,
		CipherSuite:   inspection.CipherSuite,
		ALPN:          inspection.ALPN,
		Certificates:  inspection.Certificates,
		KeyStatus:     inspection.KeyStatus,
		KeyStatusNote: inspection.KeyStatusNote,
		KeyLogLines:   inspection.KeyLogLines,
	})
}

func inspectionUseful(inspection OpenSSLInspection) bool {
	if len(inspection.KeyLogLines) > 0 {
		return true
	}
	if tlsVersion := strings.TrimSpace(inspection.TLSVersion); tlsVersion != "" && !strings.EqualFold(tlsVersion, "unknown") {
		return true
	}
	if strings.TrimSpace(inspection.CipherSuite) != "" {
		return true
	}
	if strings.TrimSpace(inspection.ALPN) != "" {
		return true
	}
	return len(inspection.Certificates) > 0
}

func inspectionComplete(inspection OpenSSLInspection) bool {
	if !inspectionUseful(inspection) {
		return false
	}
	if len(inspection.KeyLogLines) > 0 {
		return true
	}

	tlsVersion := strings.TrimSpace(inspection.TLSVersion)
	if strings.Contains(tlsVersion, "1.3") {
		return true
	}

	return false
}

func formatOpenSSLKeyMaterialLine(event ebpf.OpenSSLEvent) (string, bool) {
	label := strings.TrimSpace(event.StringPayload())
	if label == "" || event.ClientRandomLength == 0 || event.SecretLength == 0 {
		return "", false
	}
	if int(event.ClientRandomLength) > len(event.ClientRandom) || int(event.SecretLength) > len(event.Secret) {
		return "", false
	}
	clientRandom := strings.ToUpper(hex.EncodeToString(event.ClientRandom[:event.ClientRandomLength]))
	secret := strings.ToUpper(hex.EncodeToString(event.Secret[:event.SecretLength]))
	if clientRandom == "" || secret == "" {
		return "", false
	}
	return fmt.Sprintf("%s %s %s", label, clientRandom, secret), true
}

func isTLS13KeyLogLabel(label string) bool {
	switch strings.TrimSpace(label) {
	case "CLIENT_EARLY_TRAFFIC_SECRET", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "EARLY_EXPORTER_SECRET", "EXPORTER_SECRET":
		return true
	default:
		return false
	}
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
		KeyStatusNote: "matched process exited without OpenSSL or GnuTLS events; unsupported runtime or no TLS activity",
		CaptureMode:   d.Config.CaptureMode,
	})
	if finalized, ok := d.Store.Finalize(SessionKey{PID: pid, SSLPointer: 0}, d.Now()); ok {
		d.flushSnapshot(finalized)
		return
	}
	d.writeLine(RenderSessionSummary(snapshot))
}

func (d *Daemon) flushExited(
	tracked map[int]ProcessMatch,
	seenTLS map[int]bool,
	fdBySession map[SessionKey]int,
	exited map[int]time.Time,
	cutoff time.Time,
) {
	for pid, exitedAt := range exited {
		if exitedAt.After(cutoff) {
			continue
		}
		snapshots := d.Store.FinalizeByPID(pid, exitedAt)
		if len(snapshots) == 0 && tracked[pid].PID != 0 && !seenTLS[pid] {
			d.emitUnsupportedRuntime(pid, tracked[pid])
		}
		for _, snapshot := range snapshots {
			d.flushSnapshot(snapshot)
		}
		delete(tracked, pid)
		delete(seenTLS, pid)
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
		for key := range d.inspectAttempts {
			if key.PID == pid {
				delete(d.inspectAttempts, key)
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

func firstAttachedLibraryPath(loader interface{}) string {
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

func goTLSUnavailableNote(mode CaptureMode, base string) string {
	base = strings.TrimSpace(base)
	if mode != CaptureModeCapture {
		return base
	}
	if base == "" {
		return "go plaintext capture not implemented"
	}
	if strings.Contains(base, "plaintext capture not implemented") {
		return base
	}
	return base + "; plaintext capture not implemented"
}

func discoverOpenSSLLibraries() ([]string, error) {
	return discoverLibraries("libssl.so")
}

func discoverGnuTLSLibraries() ([]string, error) {
	return discoverLibraries("libgnutls.so")
}

func discoverLibraries(prefix string) ([]string, error) {
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
			if !strings.HasPrefix(info.Name(), prefix) {
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

type libraryAttacher interface {
	AttachLibraryPath(string) error
}

func attachLibrarySet(loader libraryAttacher, finder func() ([]string, error), label string) error {
	if loader == nil || finder == nil {
		return nil
	}
	paths, err := finder()
	if err != nil {
		return fmt.Errorf("discover %s libraries: %w", label, err)
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
		if err := loader.AttachLibraryPath(path); err != nil {
			return err
		}
	}
	return nil
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

func pumpGnuTLSEvents(reader gnuTLSReader, out chan<- ebpf.GnuTLSEvent, errCh chan<- error) {
	defer close(out)
	for {
		event, err := reader.ReadGnuTLSEvent()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrClosed) {
				errCh <- fmt.Errorf("read gnutls event: %w", err)
			}
			return
		}
		out <- event
	}
}

func pumpGnuTLSAppDataEvents(reader gnuTLSReader, out chan<- ebpf.GnuTLSAppDataEvent, errCh chan<- error) {
	defer close(out)
	for {
		event, err := reader.ReadGnuTLSAppDataEvent()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrClosed) {
				errCh <- fmt.Errorf("read gnutls app data event: %w", err)
			}
			return
		}
		out <- event
	}
}

func pumpGoTLSEvents(reader goTLSReader, out chan<- ebpf.GoTLSEvent, errCh chan<- error) {
	defer close(out)
	for {
		event, err := reader.ReadGoTLSEvent()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrClosed) {
				errCh <- fmt.Errorf("read go tls event: %w", err)
			}
			return
		}
		out <- event
	}
}
