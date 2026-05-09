package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type ProcessEventType uint8

const (
	ProcessEventTypeUnknown ProcessEventType = iota
	ProcessEventTypeExec
	ProcessEventTypeExit
)

const processEventSize = 24

type ProcessEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	EventType   ProcessEventType
	_           [7]byte
}

type ProcessEventLoader struct {
	objects processEventObjects
	reader  *ringbuf.Reader
	links   []link.Link
}

type processEventObjects struct {
	Exec   *cebpf.Program `ebpf:"process_exec"`
	Exit   *cebpf.Program `ebpf:"process_exit"`
	Events *cebpf.Map     `ebpf:"process_events"`
}

func NewProcessEventLoader() (*ProcessEventLoader, error) {
	spec, err := loadNamedCollectionSpec(processEventObjectFileName())
	if err != nil {
		return nil, err
	}

	var objects processEventObjects
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("load process event objects: %w", err)
	}

	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		_ = objects.Close()
		return nil, fmt.Errorf("new process event ringbuf reader: %w", err)
	}

	execLink, err := link.Tracepoint("sched", "sched_process_exec", objects.Exec, nil)
	if err != nil {
		_ = reader.Close()
		_ = objects.Close()
		return nil, fmt.Errorf("attach sched_process_exec tracepoint: %w", err)
	}
	exitLink, err := link.Tracepoint("sched", "sched_process_exit", objects.Exit, nil)
	if err != nil {
		_ = execLink.Close()
		_ = reader.Close()
		_ = objects.Close()
		return nil, fmt.Errorf("attach sched_process_exit tracepoint: %w", err)
	}

	return &ProcessEventLoader{
		objects: objects,
		reader:  reader,
		links:   []link.Link{execLink, exitLink},
	}, nil
}

func (l *ProcessEventLoader) ReadProcessEvent() (ProcessEvent, error) {
	if l == nil || l.reader == nil {
		return ProcessEvent{}, errors.New("process event reader is not initialized")
	}
	record, err := l.reader.Read()
	if err != nil {
		return ProcessEvent{}, err
	}
	return decodeProcessEvent(record.RawSample)
}

func decodeProcessEvent(raw []byte) (ProcessEvent, error) {
	if len(raw) < processEventSize {
		return ProcessEvent{}, fmt.Errorf("decode process event: got %d bytes, want %d", len(raw), processEventSize)
	}
	var event ProcessEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err != nil {
		return ProcessEvent{}, fmt.Errorf("decode process event: %w", err)
	}
	return event, nil
}

func (l *ProcessEventLoader) Close() error {
	if l == nil {
		return nil
	}
	var closeErr error
	for _, handle := range l.links {
		closeErr = errors.Join(closeErr, handle.Close())
	}
	if l.reader != nil {
		closeErr = errors.Join(closeErr, l.reader.Close())
	}
	closeErr = errors.Join(closeErr, l.objects.Close())
	return closeErr
}

func (o processEventObjects) Close() error {
	var closeErr error
	if o.Exec != nil {
		closeErr = errors.Join(closeErr, o.Exec.Close())
	}
	if o.Exit != nil {
		closeErr = errors.Join(closeErr, o.Exit.Close())
	}
	if o.Events != nil {
		closeErr = errors.Join(closeErr, o.Events.Close())
	}
	return closeErr
}

func processEventObjectFileName() string {
	var x uint16 = 0x0102
	if byte(x) == 0x02 {
		return "process_events_bpfel.o"
	}
	return "process_events_bpfeb.o"
}
