//go:build linux && amd64

package fcktls

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"unsafe"

	"github.com/moolen/FCKTLS/pkg/ebpf"
	"golang.org/x/sys/unix"
)

type GoTLSInspector interface {
	Inspect(pid int, connPtr uint64, probeKind ebpf.GoTLSProbeKind) (GoTLSInspection, bool, error)
}

type GoTLSInspection struct {
	Role          string
	SNI           string
	TLSVersion    string
	CipherSuite   string
	ALPN          string
	Certificates  []CertificateSummary
	KeyStatus     KeyStatus
	KeyStatusNote string
}

type goTLSMemoryReader interface {
	Read(pid int, addr uintptr, out []byte) error
}

type goTLSProcessVMReader struct{}

type goTLSConnInspector struct {
	reader goTLSMemoryReader
}

var (
	goTLSConnType                 = reflect.TypeOf(tls.Conn{})
	goTLSConnOffsetIsClient       = fieldOffset(goTLSConnType, "isClient")
	goTLSConnOffsetVers           = fieldOffset(goTLSConnType, "vers")
	goTLSConnOffsetCipherSuite    = fieldOffset(goTLSConnType, "cipherSuite")
	goTLSConnOffsetServerName     = fieldOffset(goTLSConnType, "serverName")
	goTLSConnOffsetClientProtocol = fieldOffset(goTLSConnType, "clientProtocol")
	goTLSSizeOfConn               = goTLSConnType.Size()
)

func newDefaultGoTLSInspector() GoTLSInspector {
	return &goTLSConnInspector{reader: goTLSProcessVMReader{}}
}

func (goTLSProcessVMReader) Read(pid int, addr uintptr, out []byte) error {
	if len(out) == 0 {
		return nil
	}

	local := []unix.Iovec{{Base: &out[0], Len: uint64(len(out))}}
	remote := []unix.RemoteIovec{{Base: addr, Len: len(out)}}
	n, err := unix.ProcessVMReadv(pid, local, remote, 0)
	if err != nil {
		return err
	}
	if n != len(out) {
		return fmt.Errorf("short read: got %d want %d", n, len(out))
	}
	return nil
}

func (i *goTLSConnInspector) Inspect(pid int, connPtr uint64, probeKind ebpf.GoTLSProbeKind) (GoTLSInspection, bool, error) {
	if i == nil || i.reader == nil || pid <= 0 || connPtr == 0 {
		return GoTLSInspection{}, false, nil
	}

	buf := make([]byte, goTLSSizeOfConn)
	if err := i.reader.Read(pid, uintptr(connPtr), buf); err != nil {
		return GoTLSInspection{}, false, err
	}

	role := goTLSProbeKindRole(probeKind, remoteBool(buf, goTLSConnOffsetIsClient))
	versionRaw := remoteUint16(buf, goTLSConnOffsetVers)
	if probeKind == ebpf.GoTLSProbeKindConnectionState && versionRaw == 0 {
		return GoTLSInspection{}, false, nil
	}

	sni, _ := i.readRemoteString(pid, remoteStringHeaderAt(buf, goTLSConnOffsetServerName))
	alpn, _ := i.readRemoteString(pid, remoteStringHeaderAt(buf, goTLSConnOffsetClientProtocol))

	inspection := GoTLSInspection{
		Role:      role,
		SNI:       sni,
		ALPN:      strings.TrimSpace(alpn),
		KeyStatus: KeyStatusUnavailable,
	}
	if versionRaw != 0 {
		inspection.TLSVersion = tls.VersionName(versionRaw)
	}
	if cipherSuite := remoteUint16(buf, goTLSConnOffsetCipherSuite); cipherSuite != 0 {
		inspection.CipherSuite = tls.CipherSuiteName(cipherSuite)
	}

	if inspection.Role == "" && inspection.SNI == "" && inspection.TLSVersion == "" && inspection.CipherSuite == "" && inspection.ALPN == "" {
		return GoTLSInspection{}, false, nil
	}

	return inspection, true, nil
}

func (i *goTLSConnInspector) readRemoteString(pid int, header remoteStringHeader) (string, error) {
	if header.Len <= 0 || header.Data == 0 {
		return "", nil
	}
	if header.Len > 1<<20 {
		header.Len = 1 << 20
	}

	buf := make([]byte, header.Len)
	if err := i.reader.Read(pid, header.Data, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

type remoteStringHeader struct {
	Data uintptr
	Len  int
}

func fieldOffset(t reflect.Type, name string) uintptr {
	field, ok := t.FieldByName(name)
	if !ok {
		panic("missing field " + t.Name() + "." + name)
	}
	return field.Offset
}

func remoteBool(buf []byte, offset uintptr) bool {
	return buf[offset] != 0
}

func remoteUint16(buf []byte, offset uintptr) uint16 {
	return binary.LittleEndian.Uint16(buf[offset : offset+2])
}

func remoteUintptr(buf []byte, offset uintptr) uintptr {
	return readUintptr(buf[offset : offset+unsafe.Sizeof(uintptr(0))])
}

func readUintptr(buf []byte) uintptr {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		return uintptr(binary.LittleEndian.Uint64(buf))
	}
	return uintptr(binary.LittleEndian.Uint32(buf))
}

func remoteStringHeaderAt(buf []byte, offset uintptr) remoteStringHeader {
	return remoteStringHeader{
		Data: remoteUintptr(buf, offset),
		Len:  int(remoteUintptr(buf, offset+unsafe.Sizeof(uintptr(0)))),
	}
}

func goTLSProbeKindRole(kind ebpf.GoTLSProbeKind, isClient bool) string {
	switch kind {
	case ebpf.GoTLSProbeKindClientHandshake:
		return "client"
	case ebpf.GoTLSProbeKindServerHandshake:
		return "server"
	default:
		if isClient {
			return "client"
		}
		return "server"
	}
}
