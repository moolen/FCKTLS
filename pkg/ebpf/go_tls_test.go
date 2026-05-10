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
	if optional["crypto/tls.(*Conn).ConnectionState"] {
		t.Fatal("ConnectionState should remain required")
	}
}
