package ebpf

import (
	"encoding/binary"
	"testing"
)

func TestDecodeOpenSSLEvent(t *testing.T) {
	t.Parallel()

	raw := make([]byte, openSSLEventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 9)
	binary.LittleEndian.PutUint32(raw[8:12], 42)
	binary.LittleEndian.PutUint32(raw[12:16], 84)
	binary.LittleEndian.PutUint64(raw[16:24], 0xfeedbeef)
	binary.LittleEndian.PutUint64(raw[24:32], 0xcafebabe)
	binary.LittleEndian.PutUint32(raw[32:36], uint32(7))
	raw[36] = byte(OpenSSLProbeKindSSLConnect)
	raw[37] = byte(OpenSSLEventTypeHandshake)
	copy(raw[40:104], []byte("example.com"))

	event, err := decodeOpenSSLEvent(raw)
	if err != nil {
		t.Fatalf("decodeOpenSSLEvent returned error: %v", err)
	}
	if event.TimestampNS != 9 {
		t.Fatalf("TimestampNS = %d, want 9", event.TimestampNS)
	}
	if event.PID != 42 {
		t.Fatalf("PID = %d, want 42", event.PID)
	}
	if event.TID != 84 {
		t.Fatalf("TID = %d, want 84", event.TID)
	}
	if event.SessionPtr != 0xfeedbeef {
		t.Fatalf("SessionPtr = %#x, want %#x", event.SessionPtr, uint64(0xfeedbeef))
	}
	if event.DataPtr != 0xcafebabe {
		t.Fatalf("DataPtr = %#x, want %#x", event.DataPtr, uint64(0xcafebabe))
	}
	if event.Value != 7 {
		t.Fatalf("Value = %d, want 7", event.Value)
	}
	if event.ProbeKind != OpenSSLProbeKindSSLConnect {
		t.Fatalf("ProbeKind = %d, want %d", event.ProbeKind, OpenSSLProbeKindSSLConnect)
	}
	if event.EventType != OpenSSLEventTypeHandshake {
		t.Fatalf("EventType = %d, want %d", event.EventType, OpenSSLEventTypeHandshake)
	}
	if got := string(event.SNIBytes[:11]); got != "example.com" {
		t.Fatalf("SNIBytes = %q, want %q", got, "example.com")
	}
	if got := event.StringPayload(); got != "" {
		t.Fatalf("StringPayload = %q, want empty string", got)
	}
}

func TestDecodeOpenSSLEventStringPayload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		eventType OpenSSLEventType
		payload   string
	}{
		{
			name:      "set sni",
			eventType: OpenSSLEventTypeSetSNI,
			payload:   "example.com",
		},
		{
			name:      "set groups",
			eventType: OpenSSLEventTypeSetGroups,
			payload:   "X25519:P-256",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			raw := make([]byte, openSSLEventSize)
			raw[37] = byte(tt.eventType)
			copy(raw[40:104], tt.payload)

			event, err := decodeOpenSSLEvent(raw)
			if err != nil {
				t.Fatalf("decodeOpenSSLEvent returned error: %v", err)
			}
			if got := event.StringPayload(); got != tt.payload {
				t.Fatalf("StringPayload = %q, want %q", got, tt.payload)
			}
		})
	}
}

func TestDecodeOpenSSLAppDataEvent(t *testing.T) {
	t.Parallel()

	raw := make([]byte, openSSLAppDataEventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 99)
	binary.LittleEndian.PutUint32(raw[8:12], 123)
	binary.LittleEndian.PutUint32(raw[12:16], 456)
	binary.LittleEndian.PutUint64(raw[16:24], 0x1111222233334444)
	binary.LittleEndian.PutUint32(raw[24:28], 128)
	binary.LittleEndian.PutUint32(raw[28:32], 5)
	raw[32] = byte(OpenSSLAppDataDirectionRead)
	copy(raw[36:], []byte("hello"))

	event, err := decodeOpenSSLAppDataEvent(raw)
	if err != nil {
		t.Fatalf("decodeOpenSSLAppDataEvent returned error: %v", err)
	}
	if event.TimestampNS != 99 {
		t.Fatalf("TimestampNS = %d, want 99", event.TimestampNS)
	}
	if event.PID != 123 {
		t.Fatalf("PID = %d, want 123", event.PID)
	}
	if event.TID != 456 {
		t.Fatalf("TID = %d, want 456", event.TID)
	}
	if event.SessionPtr != 0x1111222233334444 {
		t.Fatalf("SessionPtr = %#x, want %#x", event.SessionPtr, uint64(0x1111222233334444))
	}
	if event.DataLen != 128 {
		t.Fatalf("DataLen = %d, want 128", event.DataLen)
	}
	if event.PayloadLength != 5 {
		t.Fatalf("PayloadLength = %d, want 5", event.PayloadLength)
	}
	if event.Direction != OpenSSLAppDataDirectionRead {
		t.Fatalf("Direction = %d, want %d", event.Direction, OpenSSLAppDataDirectionRead)
	}
	if got := string(event.Payload[:5]); got != "hello" {
		t.Fatalf("Payload = %q, want %q", got, "hello")
	}
}
