package ebpf

import (
	"encoding/binary"
	"slices"
	"testing"
)

func TestDecodeGnuTLSEvent(t *testing.T) {
	raw := make([]byte, gnuTLSEventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 11)
	binary.LittleEndian.PutUint32(raw[8:12], 4242)
	binary.LittleEndian.PutUint32(raw[12:16], 4343)
	binary.LittleEndian.PutUint64(raw[16:24], 0xfeedbeef)
	raw[36] = byte(GnuTLSProbeKindHandshake)
	raw[37] = byte(GnuTLSEventTypeHandshake)
	copy(raw[40:104], []byte("NORMAL:-VERS-TLS1.3"))

	event, err := decodeGnuTLSEvent(raw)
	if err != nil {
		t.Fatalf("decodeGnuTLSEvent() error = %v", err)
	}
	if got, want := event.EventType, GnuTLSEventTypeHandshake; got != want {
		t.Fatalf("EventType = %d, want %d", got, want)
	}
	if got, want := event.StringPayload(), "NORMAL:-VERS-TLS1.3"; got != want {
		t.Fatalf("StringPayload() = %q, want %q", got, want)
	}
}

func TestDecodeGnuTLSAppDataEvent(t *testing.T) {
	raw := make([]byte, gnuTLSAppDataEventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 99)
	binary.LittleEndian.PutUint32(raw[8:12], 5150)
	binary.LittleEndian.PutUint32(raw[12:16], 6160)
	binary.LittleEndian.PutUint64(raw[16:24], 0xabad1dea)
	binary.LittleEndian.PutUint32(raw[24:28], 2048)
	binary.LittleEndian.PutUint32(raw[28:32], 18)
	raw[32] = byte(GnuTLSAppDataDirectionRead)
	copy(raw[36:], []byte("GET / HTTP/1.1\r\n\r\n"))

	event, err := decodeGnuTLSAppDataEvent(raw)
	if err != nil {
		t.Fatalf("decodeGnuTLSAppDataEvent() error = %v", err)
	}
	if got, want := event.Direction, GnuTLSAppDataDirectionRead; got != want {
		t.Fatalf("Direction = %d, want %d", got, want)
	}
	if got, want := event.PayloadLength, uint32(18); got != want {
		t.Fatalf("PayloadLength = %d, want %d", got, want)
	}
	if got, want := string(event.Payload[:event.PayloadLength]), "GET / HTTP/1.1\r\n\r\n"; got != want {
		t.Fatalf("payload = %q, want %q", got, want)
	}
}

func TestGnuTLSUprobeAttachSpecs(t *testing.T) {
	specs := gnuTLSUprobeAttachSpecs(gnuTLSObjects{})
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		names = append(names, spec.symbol)
	}
	for _, want := range []string{
		"gnutls_handshake",
		"gnutls_transport_set_int2",
		"gnutls_server_name_set",
		"gnutls_priority_set_direct",
		"gnutls_record_recv",
		"gnutls_record_send",
	} {
		if !slices.Contains(names, want) {
			t.Fatalf("attach specs missing %q", want)
		}
	}
}
