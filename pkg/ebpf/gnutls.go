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

type GnuTLSProbeKind uint8

const (
	GnuTLSProbeKindUnknown GnuTLSProbeKind = iota
	GnuTLSProbeKindHandshake
	GnuTLSProbeKindTransportSetInt2
	GnuTLSProbeKindServerNameSet
	GnuTLSProbeKindPrioritySetDirect
	GnuTLSProbeKindSessionIsResumed
	GnuTLSProbeKindVerifyStatus
	GnuTLSProbeKindGroupGet
	GnuTLSProbeKindRecordRecv
	GnuTLSProbeKindRecordSend
)

type GnuTLSEventType uint8

const (
	GnuTLSEventTypeUnknown GnuTLSEventType = iota
	GnuTLSEventTypeHandshake
	GnuTLSEventTypeSetFD
	GnuTLSEventTypeSetSNI
	GnuTLSEventTypeSetPriority
	GnuTLSEventTypeSessionResumed
	GnuTLSEventTypeVerifyStatus
	GnuTLSEventTypeNegotiatedGroup
)

type GnuTLSAppDataDirection uint8

const (
	GnuTLSAppDataDirectionUnknown GnuTLSAppDataDirection = iota
	GnuTLSAppDataDirectionRead
	GnuTLSAppDataDirectionWrite
)

func (d GnuTLSAppDataDirection) String() string {
	switch d {
	case GnuTLSAppDataDirectionRead:
		return "read"
	case GnuTLSAppDataDirectionWrite:
		return "write"
	default:
		return "unknown"
	}
}

const (
	gnuTLSEventSize        = 104
	gnuTLSMaxPayload       = 512
	gnuTLSAppDataEventSize = 32 + 1 + 3 + gnuTLSMaxPayload
)

type GnuTLSEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	SessionPtr  uint64
	DataPtr     uint64
	Value       int32
	ProbeKind   GnuTLSProbeKind
	EventType   GnuTLSEventType
	_           [2]byte
	Bytes       [64]byte
}

type GnuTLSAppDataEvent struct {
	TimestampNS   uint64
	PID           uint32
	TID           uint32
	SessionPtr    uint64
	DataLen       uint32
	PayloadLength uint32
	Direction     GnuTLSAppDataDirection
	_             [3]byte
	Payload       [gnuTLSMaxPayload]byte
}

type GnuTLSLoader struct {
	objects       gnuTLSObjects
	reader        *ringbuf.Reader
	appDataReader *ringbuf.Reader
	mu            sync.Mutex
	attachments   map[string][]link.Link
}

type gnuTLSObjects struct {
	HandshakeEnter        *cebpf.Program `ebpf:"gnutls_handshake_enter"`
	HandshakeReturn       *cebpf.Program `ebpf:"gnutls_handshake_return"`
	TransportSetInt2      *cebpf.Program `ebpf:"gnutls_transport_set_int2_enter"`
	ServerNameSetEnter    *cebpf.Program `ebpf:"gnutls_server_name_set_enter"`
	ServerNameSetReturn   *cebpf.Program `ebpf:"gnutls_server_name_set_return"`
	PrioritySetEnter      *cebpf.Program `ebpf:"gnutls_priority_set_direct_enter"`
	PrioritySetReturn     *cebpf.Program `ebpf:"gnutls_priority_set_direct_return"`
	SessionResumedEnter   *cebpf.Program `ebpf:"gnutls_session_is_resumed_enter"`
	SessionResumedReturn  *cebpf.Program `ebpf:"gnutls_session_is_resumed_return"`
	VerifyStatusEnter     *cebpf.Program `ebpf:"gnutls_session_get_verify_cert_status_enter"`
	VerifyStatusReturn    *cebpf.Program `ebpf:"gnutls_session_get_verify_cert_status_return"`
	GroupGetEnter         *cebpf.Program `ebpf:"gnutls_group_get_enter"`
	GroupGetReturn        *cebpf.Program `ebpf:"gnutls_group_get_return"`
	RecordRecvEnter       *cebpf.Program `ebpf:"gnutls_record_recv_enter"`
	RecordRecvReturn      *cebpf.Program `ebpf:"gnutls_record_recv_return"`
	RecordSendEnter       *cebpf.Program `ebpf:"gnutls_record_send_enter"`
	RecordSendReturn      *cebpf.Program `ebpf:"gnutls_record_send_return"`
	Events                *cebpf.Map     `ebpf:"gnutls_events"`
	AppDataEvents         *cebpf.Map     `ebpf:"gnutls_app_data_events"`
	Pending               *cebpf.Map     `ebpf:"gnutls_pending"`
	SNIPending            *cebpf.Map     `ebpf:"gnutls_sni_pending"`
	PriorityPending       *cebpf.Map     `ebpf:"gnutls_priority_pending"`
	SessionResumedPending *cebpf.Map     `ebpf:"gnutls_session_resumed_pending"`
	VerifyStatusPending   *cebpf.Map     `ebpf:"gnutls_verify_status_pending"`
	GroupGetPending       *cebpf.Map     `ebpf:"gnutls_group_get_pending"`
	AppDataPending        *cebpf.Map     `ebpf:"gnutls_app_data_pending"`
}

func (e GnuTLSEvent) StringPayload() string {
	end := bytes.IndexByte(e.Bytes[:], 0)
	if end == -1 {
		end = len(e.Bytes)
	}
	return string(e.Bytes[:end])
}

func NewGnuTLSLoader() (*GnuTLSLoader, error) {
	spec, err := loadNamedCollectionSpec(gnuTLSObjectFileName())
	if err != nil {
		return nil, err
	}

	var objects gnuTLSObjects
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("load gnutls uprobe objects: %w", err)
	}

	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		_ = objects.Close()
		return nil, fmt.Errorf("new gnutls ringbuf reader: %w", err)
	}

	appReader, err := ringbuf.NewReader(objects.AppDataEvents)
	if err != nil {
		_ = reader.Close()
		_ = objects.Close()
		return nil, fmt.Errorf("new gnutls app data ringbuf reader: %w", err)
	}

	return &GnuTLSLoader{
		objects:       objects,
		reader:        reader,
		appDataReader: appReader,
		attachments:   make(map[string][]link.Link),
	}, nil
}

func (l *GnuTLSLoader) AttachLibraryPath(libraryPath string) error {
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

	links, err := attachUprobeSpecs(executable, libraryPath, gnuTLSUprobeAttachSpecs(l.objects))
	if err != nil {
		return err
	}

	l.mu.Lock()
	l.attachments[libraryPath] = links
	l.mu.Unlock()
	return nil
}

func (l *GnuTLSLoader) ReadGnuTLSEvent() (GnuTLSEvent, error) {
	if l == nil || l.reader == nil {
		return GnuTLSEvent{}, errors.New("gnutls reader is not initialized")
	}

	record, err := l.reader.Read()
	if err != nil {
		return GnuTLSEvent{}, err
	}

	return decodeGnuTLSEvent(record.RawSample)
}

func (l *GnuTLSLoader) ReadGnuTLSAppDataEvent() (GnuTLSAppDataEvent, error) {
	if l == nil || l.appDataReader == nil {
		return GnuTLSAppDataEvent{}, errors.New("gnutls app data reader is not initialized")
	}

	record, err := l.appDataReader.Read()
	if err != nil {
		return GnuTLSAppDataEvent{}, err
	}

	return decodeGnuTLSAppDataEvent(record.RawSample)
}

func decodeGnuTLSEvent(raw []byte) (GnuTLSEvent, error) {
	if len(raw) < gnuTLSEventSize {
		return GnuTLSEvent{}, fmt.Errorf("decode gnutls event: got %d bytes, want %d", len(raw), gnuTLSEventSize)
	}

	var event GnuTLSEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err != nil {
		return GnuTLSEvent{}, fmt.Errorf("decode gnutls event: %w", err)
	}
	return event, nil
}

func decodeGnuTLSAppDataEvent(raw []byte) (GnuTLSAppDataEvent, error) {
	if len(raw) < gnuTLSAppDataEventSize {
		return GnuTLSAppDataEvent{}, fmt.Errorf("decode gnutls app data event: got %d bytes, want %d", len(raw), gnuTLSAppDataEventSize)
	}

	var event GnuTLSAppDataEvent
	event.TimestampNS = binary.LittleEndian.Uint64(raw[0:8])
	event.PID = binary.LittleEndian.Uint32(raw[8:12])
	event.TID = binary.LittleEndian.Uint32(raw[12:16])
	event.SessionPtr = binary.LittleEndian.Uint64(raw[16:24])
	event.DataLen = binary.LittleEndian.Uint32(raw[24:28])
	event.PayloadLength = binary.LittleEndian.Uint32(raw[28:32])
	event.Direction = GnuTLSAppDataDirection(raw[32])
	if event.PayloadLength > gnuTLSMaxPayload {
		return GnuTLSAppDataEvent{}, fmt.Errorf("decode gnutls app data event: payload length %d exceeds buffer %d", event.PayloadLength, gnuTLSMaxPayload)
	}
	copy(event.Payload[:], raw[36:36+gnuTLSMaxPayload])
	return event, nil
}

func (l *GnuTLSLoader) Close() error {
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

func (l *GnuTLSLoader) AttachedLibraryPaths() []string {
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

func (o gnuTLSObjects) Close() error {
	var closeErr error
	for _, prog := range []*cebpf.Program{
		o.HandshakeEnter,
		o.HandshakeReturn,
		o.TransportSetInt2,
		o.ServerNameSetEnter,
		o.ServerNameSetReturn,
		o.PrioritySetEnter,
		o.PrioritySetReturn,
		o.SessionResumedEnter,
		o.SessionResumedReturn,
		o.VerifyStatusEnter,
		o.VerifyStatusReturn,
		o.GroupGetEnter,
		o.GroupGetReturn,
		o.RecordRecvEnter,
		o.RecordRecvReturn,
		o.RecordSendEnter,
		o.RecordSendReturn,
	} {
		if prog != nil {
			closeErr = errors.Join(closeErr, prog.Close())
		}
	}
	for _, m := range []*cebpf.Map{
		o.Events,
		o.AppDataEvents,
		o.Pending,
		o.SNIPending,
		o.PriorityPending,
		o.SessionResumedPending,
		o.VerifyStatusPending,
		o.GroupGetPending,
		o.AppDataPending,
	} {
		if m != nil {
			closeErr = errors.Join(closeErr, m.Close())
		}
	}
	return closeErr
}

func gnuTLSUprobeAttachSpecs(objects gnuTLSObjects) []uprobeAttachSpec {
	return []uprobeAttachSpec{
		{symbol: "gnutls_handshake", enter: objects.HandshakeEnter, ret: objects.HandshakeReturn},
		{symbol: "gnutls_transport_set_int2", enter: objects.TransportSetInt2},
		{symbol: "gnutls_server_name_set", enter: objects.ServerNameSetEnter, ret: objects.ServerNameSetReturn},
		{symbol: "gnutls_priority_set_direct", enter: objects.PrioritySetEnter, ret: objects.PrioritySetReturn, optional: true},
		{symbol: "gnutls_session_is_resumed", enter: objects.SessionResumedEnter, ret: objects.SessionResumedReturn, optional: true},
		{symbol: "gnutls_session_get_verify_cert_status", enter: objects.VerifyStatusEnter, ret: objects.VerifyStatusReturn, optional: true},
		{symbol: "gnutls_group_get", enter: objects.GroupGetEnter, ret: objects.GroupGetReturn, optional: true},
		{symbol: "gnutls_record_recv", enter: objects.RecordRecvEnter, ret: objects.RecordRecvReturn, optional: true},
		{symbol: "gnutls_record_send", enter: objects.RecordSendEnter, ret: objects.RecordSendReturn, optional: true},
	}
}

func gnuTLSObjectFileName() string {
	var x uint16 = 0x0102
	if byte(x) == 0x02 {
		return "gnutls_uprobe_bpfel.o"
	}
	return "gnutls_uprobe_bpfeb.o"
}
