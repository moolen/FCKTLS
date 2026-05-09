package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type OpenSSLProbeKind uint8

const (
	OpenSSLProbeKindUnknown OpenSSLProbeKind = iota
	OpenSSLProbeKindSSLConnect
	OpenSSLProbeKindSSLAccept
	OpenSSLProbeKindSSLDoHandshake
)

func (k OpenSSLProbeKind) String() string {
	switch k {
	case OpenSSLProbeKindSSLConnect:
		return "ssl_connect"
	case OpenSSLProbeKindSSLAccept:
		return "ssl_accept"
	case OpenSSLProbeKindSSLDoHandshake:
		return "ssl_do_handshake"
	default:
		return "unknown"
	}
}

func (k OpenSSLProbeKind) Symbol() string {
	switch k {
	case OpenSSLProbeKindSSLConnect:
		return "SSL_connect"
	case OpenSSLProbeKindSSLAccept:
		return "SSL_accept"
	case OpenSSLProbeKindSSLDoHandshake:
		return "SSL_do_handshake"
	default:
		return ""
	}
}

type OpenSSLEventType uint8

const (
	OpenSSLEventTypeUnknown OpenSSLEventType = iota
	OpenSSLEventTypeHandshake
	OpenSSLEventTypeSetFD
	OpenSSLEventTypeSetSNI
	OpenSSLEventTypeSetGroups
	OpenSSLEventTypeSetVerify
	OpenSSLEventTypeSessionReused
	OpenSSLEventTypeVerifyResult
	OpenSSLEventTypeNegotiatedGroup
)

func (t OpenSSLEventType) String() string {
	switch t {
	case OpenSSLEventTypeHandshake:
		return "handshake"
	case OpenSSLEventTypeSetFD:
		return "set_fd"
	case OpenSSLEventTypeSetSNI:
		return "set_sni"
	case OpenSSLEventTypeSetGroups:
		return "set_groups"
	case OpenSSLEventTypeSetVerify:
		return "set_verify"
	case OpenSSLEventTypeSessionReused:
		return "session_reused"
	case OpenSSLEventTypeVerifyResult:
		return "verify_result"
	case OpenSSLEventTypeNegotiatedGroup:
		return "negotiated_group"
	default:
		return "unknown"
	}
}

type OpenSSLAppDataDirection uint8

const (
	OpenSSLAppDataDirectionUnknown OpenSSLAppDataDirection = iota
	OpenSSLAppDataDirectionRead
	OpenSSLAppDataDirectionWrite
)

func (d OpenSSLAppDataDirection) String() string {
	switch d {
	case OpenSSLAppDataDirectionRead:
		return "read"
	case OpenSSLAppDataDirectionWrite:
		return "write"
	default:
		return "unknown"
	}
}

const (
	openSSLEventSize        = 104
	openSSLMaxPayload       = 512
	openSSLAppDataEventSize = 32 + 1 + 3 + openSSLMaxPayload
)

type OpenSSLEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	SessionPtr  uint64
	DataPtr     uint64
	Value       int32
	ProbeKind   OpenSSLProbeKind
	EventType   OpenSSLEventType
	_           [2]byte
	SNIBytes    [64]byte
}

type OpenSSLAppDataEvent struct {
	TimestampNS   uint64
	PID           uint32
	TID           uint32
	SessionPtr    uint64
	DataLen       uint32
	PayloadLength uint32
	Direction     OpenSSLAppDataDirection
	_             [3]byte
	Payload       [openSSLMaxPayload]byte
}

type OpenSSLLoader struct {
	objects       openSSLObjects
	reader        *ringbuf.Reader
	appDataReader *ringbuf.Reader
	mu            sync.Mutex
	attachments   map[string][]link.Link
}

type openSSLObjects struct {
	SSLConnectEnter             *cebpf.Program `ebpf:"openssl_ssl_connect_enter"`
	SSLConnectReturn            *cebpf.Program `ebpf:"openssl_ssl_connect_return"`
	SSLAcceptEnter              *cebpf.Program `ebpf:"openssl_ssl_accept_enter"`
	SSLAcceptReturn             *cebpf.Program `ebpf:"openssl_ssl_accept_return"`
	SSLDoHandshakeEnter         *cebpf.Program `ebpf:"openssl_ssl_do_handshake_enter"`
	SSLDoHandshakeRet           *cebpf.Program `ebpf:"openssl_ssl_do_handshake_return"`
	SSLSetFDEnter               *cebpf.Program `ebpf:"openssl_ssl_set_fd_enter"`
	SSLSetFDReturn              *cebpf.Program `ebpf:"openssl_ssl_set_fd_return"`
	SSLCtrlEnter                *cebpf.Program `ebpf:"openssl_ssl_ctrl_enter"`
	SSLCtrlReturn               *cebpf.Program `ebpf:"openssl_ssl_ctrl_return"`
	SSLSetGroupsEnter           *cebpf.Program `ebpf:"openssl_ssl_set_groups_list_enter"`
	SSLSetGroupsReturn          *cebpf.Program `ebpf:"openssl_ssl_set_groups_list_return"`
	SSLSetVerifyEnter           *cebpf.Program `ebpf:"openssl_ssl_set_verify_enter"`
	SSLSessionReusedEnter       *cebpf.Program `ebpf:"openssl_ssl_session_reused_enter"`
	SSLSessionReusedReturn      *cebpf.Program `ebpf:"openssl_ssl_session_reused_return"`
	SSLGetVerifyResultEnter     *cebpf.Program `ebpf:"openssl_ssl_get_verify_result_enter"`
	SSLGetVerifyResultReturn    *cebpf.Program `ebpf:"openssl_ssl_get_verify_result_return"`
	SSLGetNegotiatedGroupEnter  *cebpf.Program `ebpf:"openssl_ssl_get_negotiated_group_enter"`
	SSLGetNegotiatedGroupReturn *cebpf.Program `ebpf:"openssl_ssl_get_negotiated_group_return"`
	SSLReadEnter                *cebpf.Program `ebpf:"openssl_ssl_read_enter"`
	SSLReadReturn               *cebpf.Program `ebpf:"openssl_ssl_read_return"`
	SSLWriteEnter               *cebpf.Program `ebpf:"openssl_ssl_write_enter"`
	SSLWriteReturn              *cebpf.Program `ebpf:"openssl_ssl_write_return"`
	Events                      *cebpf.Map     `ebpf:"openssl_events"`
	AppDataEvents               *cebpf.Map     `ebpf:"openssl_app_data_events"`
	Pending                     *cebpf.Map     `ebpf:"openssl_pending"`
	FDPending                   *cebpf.Map     `ebpf:"openssl_fd_pending"`
	SNIPending                  *cebpf.Map     `ebpf:"openssl_sni_pending"`
	GroupsPending               *cebpf.Map     `ebpf:"openssl_groups_pending"`
	SessionReusedPending        *cebpf.Map     `ebpf:"openssl_session_reused_pending"`
	VerifyResultPending         *cebpf.Map     `ebpf:"openssl_verify_result_pending"`
	NegotiatedGroupPending      *cebpf.Map     `ebpf:"openssl_negotiated_group_pending"`
	AppDataPending              *cebpf.Map     `ebpf:"openssl_app_data_pending"`
}

func NewOpenSSLLoader() (*OpenSSLLoader, error) {
	spec, err := loadNamedCollectionSpec(openSSLObjectFileName())
	if err != nil {
		return nil, err
	}

	var objects openSSLObjects
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("load openssl uprobe objects: %w", err)
	}

	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		_ = objects.Close()
		return nil, fmt.Errorf("new openssl ringbuf reader: %w", err)
	}
	appReader, err := ringbuf.NewReader(objects.AppDataEvents)
	if err != nil {
		_ = reader.Close()
		_ = objects.Close()
		return nil, fmt.Errorf("new openssl app data ringbuf reader: %w", err)
	}

	return &OpenSSLLoader{
		objects:       objects,
		reader:        reader,
		appDataReader: appReader,
		attachments:   make(map[string][]link.Link),
	}, nil
}

func (l *OpenSSLLoader) AttachLibraryPath(libraryPath string) error {
	if libraryPath == "" {
		return fmt.Errorf("library path is required")
	}

	l.mu.Lock()
	if _, ok := l.attachments[libraryPath]; ok {
		l.mu.Unlock()
		return nil
	}
	l.mu.Unlock()

	executable, err := link.OpenExecutable(libraryPath)
	if err != nil {
		return fmt.Errorf("open shared library %q: %w", libraryPath, err)
	}

	links, err := attachUprobeSpecs(executable, libraryPath, openSSLUprobeAttachSpecs(l.objects))
	if err != nil {
		return err
	}

	l.mu.Lock()
	l.attachments[libraryPath] = links
	l.mu.Unlock()
	return nil
}

func (l *OpenSSLLoader) ReadOpenSSLEvent() (OpenSSLEvent, error) {
	if l == nil || l.reader == nil {
		return OpenSSLEvent{}, errors.New("openssl reader is not initialized")
	}
	record, err := l.reader.Read()
	if err != nil {
		return OpenSSLEvent{}, err
	}
	return decodeOpenSSLEvent(record.RawSample)
}

func (l *OpenSSLLoader) ReadOpenSSLAppDataEvent() (OpenSSLAppDataEvent, error) {
	if l == nil || l.appDataReader == nil {
		return OpenSSLAppDataEvent{}, errors.New("openssl app data reader is not initialized")
	}
	record, err := l.appDataReader.Read()
	if err != nil {
		return OpenSSLAppDataEvent{}, err
	}
	return decodeOpenSSLAppDataEvent(record.RawSample)
}

func decodeOpenSSLEvent(raw []byte) (OpenSSLEvent, error) {
	if len(raw) < openSSLEventSize {
		return OpenSSLEvent{}, fmt.Errorf("decode openssl event: got %d bytes, want %d", len(raw), openSSLEventSize)
	}
	var event OpenSSLEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err != nil {
		return OpenSSLEvent{}, fmt.Errorf("decode openssl event: %w", err)
	}
	return event, nil
}

func decodeOpenSSLAppDataEvent(raw []byte) (OpenSSLAppDataEvent, error) {
	if len(raw) < openSSLAppDataEventSize {
		return OpenSSLAppDataEvent{}, fmt.Errorf("decode openssl app data event: got %d bytes, want %d", len(raw), openSSLAppDataEventSize)
	}
	var event OpenSSLAppDataEvent
	event.TimestampNS = binary.LittleEndian.Uint64(raw[0:8])
	event.PID = binary.LittleEndian.Uint32(raw[8:12])
	event.TID = binary.LittleEndian.Uint32(raw[12:16])
	event.SessionPtr = binary.LittleEndian.Uint64(raw[16:24])
	event.DataLen = binary.LittleEndian.Uint32(raw[24:28])
	event.PayloadLength = binary.LittleEndian.Uint32(raw[28:32])
	event.Direction = OpenSSLAppDataDirection(raw[32])
	if event.PayloadLength > openSSLMaxPayload {
		return OpenSSLAppDataEvent{}, fmt.Errorf("decode openssl app data event: payload length %d exceeds buffer %d", event.PayloadLength, openSSLMaxPayload)
	}
	copy(event.Payload[:], raw[36:36+openSSLMaxPayload])
	return event, nil
}

func (l *OpenSSLLoader) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	for key, links := range l.attachments {
		closeLinks(links)
		delete(l.attachments, key)
	}
	l.mu.Unlock()

	var closeErr error
	if l.reader != nil {
		closeErr = errors.Join(closeErr, l.reader.Close())
	}
	if l.appDataReader != nil {
		closeErr = errors.Join(closeErr, l.appDataReader.Close())
	}
	closeErr = errors.Join(closeErr, l.objects.Close())
	return closeErr
}

func (l *OpenSSLLoader) AttachedLibraryPaths() []string {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	out := make([]string, 0, len(l.attachments))
	for path := range l.attachments {
		out = append(out, path)
	}
	return out
}

func (o openSSLObjects) Close() error {
	var closeErr error
	for _, prog := range []*cebpf.Program{
		o.SSLConnectEnter,
		o.SSLConnectReturn,
		o.SSLAcceptEnter,
		o.SSLAcceptReturn,
		o.SSLDoHandshakeEnter,
		o.SSLDoHandshakeRet,
		o.SSLSetFDEnter,
		o.SSLSetFDReturn,
		o.SSLCtrlEnter,
		o.SSLCtrlReturn,
		o.SSLSetGroupsEnter,
		o.SSLSetGroupsReturn,
		o.SSLSetVerifyEnter,
		o.SSLSessionReusedEnter,
		o.SSLSessionReusedReturn,
		o.SSLGetVerifyResultEnter,
		o.SSLGetVerifyResultReturn,
		o.SSLGetNegotiatedGroupEnter,
		o.SSLGetNegotiatedGroupReturn,
		o.SSLReadEnter,
		o.SSLReadReturn,
		o.SSLWriteEnter,
		o.SSLWriteReturn,
	} {
		if prog != nil {
			closeErr = errors.Join(closeErr, prog.Close())
		}
	}
	for _, m := range []*cebpf.Map{
		o.Events,
		o.AppDataEvents,
		o.Pending,
		o.FDPending,
		o.SNIPending,
		o.GroupsPending,
		o.SessionReusedPending,
		o.VerifyResultPending,
		o.NegotiatedGroupPending,
		o.AppDataPending,
	} {
		if m != nil {
			closeErr = errors.Join(closeErr, m.Close())
		}
	}
	return closeErr
}

func openSSLUprobeAttachSpecs(objects openSSLObjects) []uprobeAttachSpec {
	return []uprobeAttachSpec{
		{symbol: "SSL_connect", enter: objects.SSLConnectEnter, ret: objects.SSLConnectReturn},
		{symbol: "SSL_accept", enter: objects.SSLAcceptEnter, ret: objects.SSLAcceptReturn},
		{symbol: "SSL_do_handshake", enter: objects.SSLDoHandshakeEnter, ret: objects.SSLDoHandshakeRet},
		{symbol: "SSL_set_fd", enter: objects.SSLSetFDEnter, ret: objects.SSLSetFDReturn},
		{symbol: "SSL_ctrl", enter: objects.SSLCtrlEnter, ret: objects.SSLCtrlReturn},
		{symbol: "SSL_set1_groups_list", enter: objects.SSLSetGroupsEnter, ret: objects.SSLSetGroupsReturn, optional: true},
		{symbol: "SSL_set_verify", enter: objects.SSLSetVerifyEnter, optional: true},
		{symbol: "SSL_session_reused", enter: objects.SSLSessionReusedEnter, ret: objects.SSLSessionReusedReturn, optional: true},
		{symbol: "SSL_get_verify_result", enter: objects.SSLGetVerifyResultEnter, ret: objects.SSLGetVerifyResultReturn, optional: true},
		{symbol: "SSL_get_negotiated_group", enter: objects.SSLGetNegotiatedGroupEnter, ret: objects.SSLGetNegotiatedGroupReturn, optional: true},
		{symbol: "SSL_read", enter: objects.SSLReadEnter, ret: objects.SSLReadReturn, optional: true},
		{symbol: "SSL_write", enter: objects.SSLWriteEnter, ret: objects.SSLWriteReturn, optional: true},
	}
}

func openSSLObjectFileName() string {
	var x uint16 = 0x0102
	if byte(x) == 0x02 {
		return "openssl_uprobe_bpfel.o"
	}
	return "openssl_uprobe_bpfeb.o"
}
