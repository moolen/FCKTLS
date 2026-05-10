package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type GoTLSProbeKind uint8

const (
	GoTLSProbeKindUnknown GoTLSProbeKind = iota
	GoTLSProbeKindClientHandshake
	GoTLSProbeKindServerHandshake
	GoTLSProbeKindConnectionState
)

func (k GoTLSProbeKind) String() string {
	switch k {
	case GoTLSProbeKindClientHandshake:
		return "client_handshake"
	case GoTLSProbeKindServerHandshake:
		return "server_handshake"
	case GoTLSProbeKindConnectionState:
		return "connection_state"
	default:
		return "unknown"
	}
}

const goTLSEventSize = 32

type GoTLSEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	ConnPtr     uint64
	ProbeKind   GoTLSProbeKind
	_           [7]byte
}

type GoTLSLoader struct {
	objects     goTLSObjects
	reader      *ringbuf.Reader
	mu          sync.Mutex
	attachments map[int][]link.Link
}

type goTLSObjects struct {
	ClientHandshakeEnter *cebpf.Program `ebpf:"go_tls_client_handshake_enter"`
	ServerHandshakeEnter *cebpf.Program `ebpf:"go_tls_server_handshake_enter"`
	ConnectionState      *cebpf.Program `ebpf:"go_tls_connection_state"`
	Events               *cebpf.Map     `ebpf:"go_tls_events"`
	PIDNamespaceConfig   *cebpf.Map     `ebpf:"go_tls_pidns_config_map"`
}

type goTLSPIDNamespaceConfig struct {
	Dev uint64
	Ino uint64
}

func NewGoTLSLoader() (*GoTLSLoader, error) {
	spec, err := loadNamedCollectionSpec(goTLSObjectFileName())
	if err != nil {
		return nil, err
	}

	var objects goTLSObjects
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("load go tls uprobe objects: %w", err)
	}
	if err := initializeGoTLSPIDNamespace(objects.PIDNamespaceConfig); err != nil {
		_ = objects.Close()
		return nil, fmt.Errorf("initialize go tls pid namespace: %w", err)
	}

	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		_ = objects.Close()
		return nil, fmt.Errorf("new go tls ringbuf reader: %w", err)
	}

	return &GoTLSLoader{
		objects:     objects,
		reader:      reader,
		attachments: make(map[int][]link.Link),
	}, nil
}

func (l *GoTLSLoader) AttachProcess(pid int, executablePath string) error {
	if pid <= 0 {
		return fmt.Errorf("pid must be positive")
	}
	if strings.TrimSpace(executablePath) == "" {
		return fmt.Errorf("executable path is required")
	}

	l.mu.Lock()
	if _, ok := l.attachments[pid]; ok {
		l.mu.Unlock()
		return nil
	}
	l.mu.Unlock()

	executable, err := link.OpenExecutable(executablePath)
	if err != nil {
		return fmt.Errorf("open executable %q: %w", executablePath, err)
	}

	links, err := attachUprobeSpecsWithOps(
		executablePath,
		goTLSUprobeAttachSpecs(l.objects),
		func(symbol string, prog *cebpf.Program) (link.Link, error) {
			return executable.Uprobe(symbol, prog, &link.UprobeOptions{PID: pid})
		},
		func(symbol string, prog *cebpf.Program) (link.Link, error) {
			return executable.Uretprobe(symbol, prog, &link.UprobeOptions{PID: pid})
		},
	)
	if err != nil {
		return err
	}

	l.mu.Lock()
	l.attachments[pid] = links
	l.mu.Unlock()
	return nil
}

func (l *GoTLSLoader) ReadGoTLSEvent() (GoTLSEvent, error) {
	if l == nil || l.reader == nil {
		return GoTLSEvent{}, errors.New("go tls reader is not initialized")
	}

	record, err := l.reader.Read()
	if err != nil {
		return GoTLSEvent{}, err
	}

	return decodeGoTLSEvent(record.RawSample)
}

func decodeGoTLSEvent(raw []byte) (GoTLSEvent, error) {
	if len(raw) < goTLSEventSize {
		return GoTLSEvent{}, fmt.Errorf("decode go tls event: got %d bytes, want %d", len(raw), goTLSEventSize)
	}

	var event GoTLSEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err != nil {
		return GoTLSEvent{}, fmt.Errorf("decode go tls event: %w", err)
	}
	return event, nil
}

func (l *GoTLSLoader) Close() error {
	if l == nil {
		return nil
	}

	l.mu.Lock()
	for pid, links := range l.attachments {
		closeLinks(links)
		delete(l.attachments, pid)
	}
	l.mu.Unlock()

	var closeErr error
	if l.reader != nil {
		closeErr = errors.Join(closeErr, l.reader.Close())
	}
	closeErr = errors.Join(closeErr, l.objects.Close())
	return closeErr
}

func (o goTLSObjects) Close() error {
	var closeErr error
	for _, prog := range []*cebpf.Program{
		o.ClientHandshakeEnter,
		o.ServerHandshakeEnter,
		o.ConnectionState,
	} {
		if prog != nil {
			closeErr = errors.Join(closeErr, prog.Close())
		}
	}
	for _, m := range []*cebpf.Map{
		o.Events,
		o.PIDNamespaceConfig,
	} {
		if m != nil {
			closeErr = errors.Join(closeErr, m.Close())
		}
	}
	return closeErr
}

func initializeGoTLSPIDNamespace(m *cebpf.Map) error {
	if m == nil {
		return nil
	}
	cfg, err := currentPIDNamespaceConfig()
	if err != nil {
		return err
	}
	key := uint32(0)
	if err := m.Update(&key, &cfg, cebpf.UpdateAny); err != nil {
		return fmt.Errorf("update pid namespace map: %w", err)
	}
	return nil
}

func currentPIDNamespaceConfig() (goTLSPIDNamespaceConfig, error) {
	info, err := os.Stat("/proc/self/ns/pid")
	if err != nil {
		return goTLSPIDNamespaceConfig{}, fmt.Errorf("stat /proc/self/ns/pid: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return goTLSPIDNamespaceConfig{}, fmt.Errorf("unexpected stat payload type %T", info.Sys())
	}
	return goTLSPIDNamespaceConfig{
		Dev: uint64(stat.Dev),
		Ino: uint64(stat.Ino),
	}, nil
}

func goTLSUprobeAttachSpecs(objects goTLSObjects) []uprobeAttachSpec {
	return []uprobeAttachSpec{
		{symbol: "crypto/tls.(*Conn).clientHandshake", enter: objects.ClientHandshakeEnter, optional: true},
		{symbol: "crypto/tls.(*Conn).serverHandshake", enter: objects.ServerHandshakeEnter, optional: true},
		{symbol: "crypto/tls.(*Conn).ConnectionState", enter: objects.ConnectionState},
	}
}

func goTLSObjectFileName() string {
	var x uint16 = 0x0102
	if byte(x) == 0x02 {
		return "go_tls_uprobe_bpfel.o"
	}
	return "go_tls_uprobe_bpfeb.o"
}
