package ebpf

import (
	"encoding/binary"
	"slices"
	"testing"
)

func TestDecodeGoTLSEvent(t *testing.T) {
	raw := make([]byte, goTLSEventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 123)
	binary.LittleEndian.PutUint32(raw[8:12], 4242)
	binary.LittleEndian.PutUint32(raw[12:16], 4343)
	binary.LittleEndian.PutUint64(raw[16:24], 0xfeedbeef)
	raw[24] = byte(GoTLSProbeKindClientHandshake)

	event, err := decodeGoTLSEvent(raw)
	if err != nil {
		t.Fatalf("decodeGoTLSEvent() error = %v", err)
	}
	if got, want := event.ProbeKind, GoTLSProbeKindClientHandshake; got != want {
		t.Fatalf("ProbeKind = %d, want %d", got, want)
	}
}

func TestDecodeGoTLSAppDataEvent(t *testing.T) {
	raw := make([]byte, goTLSAppDataEventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 99)
	binary.LittleEndian.PutUint32(raw[8:12], 5150)
	binary.LittleEndian.PutUint32(raw[12:16], 6160)
	binary.LittleEndian.PutUint64(raw[16:24], 0xabad1dea)
	binary.LittleEndian.PutUint32(raw[24:28], 16)
	raw[28] = byte(GoTLSAppDataDirectionWrite)
	copy(raw[32:], []byte("GET / HTTP/1.1\r\n"))

	event, err := decodeGoTLSAppDataEvent(raw)
	if err != nil {
		t.Fatalf("decodeGoTLSAppDataEvent() error = %v", err)
	}
	if got, want := event.PID, uint32(5150); got != want {
		t.Fatalf("PID = %d, want %d", got, want)
	}
	if got, want := event.ConnPtr, uint64(0xabad1dea); got != want {
		t.Fatalf("ConnPtr = %#x, want %#x", got, want)
	}
	if got, want := event.Direction, GoTLSAppDataDirectionWrite; got != want {
		t.Fatalf("Direction = %d, want %d", got, want)
	}
	if got, want := event.PayloadLength, uint32(16); got != want {
		t.Fatalf("PayloadLength = %d, want %d", got, want)
	}
	if got, want := string(event.Payload[:event.PayloadLength]), "GET / HTTP/1.1\r\n"; got != want {
		t.Fatalf("payload = %q, want %q", got, want)
	}
}

func TestGoTLSAttachSpecs(t *testing.T) {
	specs := goTLSUprobeAttachSpecs(goTLSObjects{})
	names := make([]string, 0, len(specs))
	optional := make(map[string]bool, len(specs))
	for _, spec := range specs {
		names = append(names, spec.symbol)
		optional[spec.symbol] = spec.optional
	}
	for _, want := range []string{
		"crypto/tls.(*Conn).clientHandshake",
		"crypto/tls.(*Conn).serverHandshake",
		"crypto/tls.(*Conn).ConnectionState",
		"crypto/tls.(*Conn).Write",
		"crypto/tls.(*Conn).Read",
	} {
		if !slices.Contains(names, want) {
			t.Fatalf("attach specs missing %q", want)
		}
	}
	if !optional["crypto/tls.(*Conn).clientHandshake"] {
		t.Fatal("clientHandshake should be optional for client-only binaries")
	}
	if !optional["crypto/tls.(*Conn).serverHandshake"] {
		t.Fatal("serverHandshake should be optional for client-only binaries")
	}
	if !optional["crypto/tls.(*Conn).Write"] {
		t.Fatal("Write should be optional for metadata-only support")
	}
	if !optional["crypto/tls.(*Conn).Read"] {
		t.Fatal("Read should be optional for metadata-only support")
	}
	if optional["crypto/tls.(*Conn).ConnectionState"] {
		t.Fatal("ConnectionState should remain required")
	}
}
