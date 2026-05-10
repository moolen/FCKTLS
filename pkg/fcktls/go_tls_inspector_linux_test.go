//go:build linux && amd64

package fcktls

import (
	"crypto/tls"
	"os"
	"reflect"
	"testing"
	"unsafe"

	"github.com/moolen/FCKTLS/pkg/ebpf"
)

type localGoTLSMemoryReader struct{}

func (localGoTLSMemoryReader) Read(pid int, addr uintptr, out []byte) error {
	src := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(out))
	copy(out, src)
	return nil
}

func TestGoTLSInspectorReadsLocalConnState(t *testing.T) {
	conn := &tls.Conn{}
	setUnexportedField(t, conn, "isClient", true)
	setUnexportedField(t, conn, "vers", uint16(tls.VersionTLS13))
	setUnexportedField(t, conn, "cipherSuite", uint16(tls.TLS_AES_128_GCM_SHA256))
	setUnexportedField(t, conn, "serverName", "example.com")
	setUnexportedField(t, conn, "clientProtocol", "h2")

	inspector := &goTLSConnInspector{reader: localGoTLSMemoryReader{}}
	inspection, ok, err := inspector.Inspect(os.Getpid(), uint64(uintptr(unsafe.Pointer(conn))), ebpf.GoTLSProbeKindConnectionState)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !ok {
		t.Fatal("Inspect() ok = false, want true")
	}
	if got, want := inspection.Role, "client"; got != want {
		t.Fatalf("Role = %q, want %q", got, want)
	}
	if got, want := inspection.SNI, "example.com"; got != want {
		t.Fatalf("SNI = %q, want %q", got, want)
	}
	if got, want := inspection.TLSVersion, "TLS 1.3"; got != want {
		t.Fatalf("TLSVersion = %q, want %q", got, want)
	}
	if got, want := inspection.CipherSuite, "TLS_AES_128_GCM_SHA256"; got != want {
		t.Fatalf("CipherSuite = %q, want %q", got, want)
	}
	if got, want := inspection.ALPN, "h2"; got != want {
		t.Fatalf("ALPN = %q, want %q", got, want)
	}
}

func setUnexportedField(t *testing.T, target any, name string, value any) {
	t.Helper()

	field := reflect.ValueOf(target).Elem().FieldByName(name)
	if !field.IsValid() {
		t.Fatalf("field %q not found", name)
	}
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(value))
}
