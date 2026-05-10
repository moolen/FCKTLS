package fcktls

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectGoBinaryRejectsMissingTLSSymbols(t *testing.T) {
	info := goBinaryInspection{
		IsGoBinary: true,
		Symbols: map[string]struct{}{
			"main.main": {},
		},
	}

	if info.SupportsCryptoTLS() {
		t.Fatal("SupportsCryptoTLS() = true, want false")
	}
}

func TestInspectGoBinaryAcceptsRequiredTLSSymbols(t *testing.T) {
	info := goBinaryInspection{
		IsGoBinary: true,
		Symbols: map[string]struct{}{
			goTLSClientHandshakeSymbol: {},
			goTLSConnectionStateSymbol: {},
		},
	}

	if !info.SupportsCryptoTLS() {
		t.Fatal("SupportsCryptoTLS() = false, want true")
	}
}

func TestInspectGoBinaryAcceptsServerOnlyTLSSymbols(t *testing.T) {
	info := goBinaryInspection{
		IsGoBinary: true,
		Symbols: map[string]struct{}{
			goTLSServerHandshakeSymbol: {},
			goTLSConnectionStateSymbol: {},
		},
	}

	if !info.SupportsCryptoTLS() {
		t.Fatal("SupportsCryptoTLS() = false, want true")
	}
}

func TestInspectGoBinaryReportsGoExecutableMetadata(t *testing.T) {
	path := buildGoTLSFixture(t)

	info, err := InspectGoBinary(path)
	if err != nil {
		t.Fatalf("InspectGoBinary() error = %v", err)
	}

	if !info.IsGoBinary {
		t.Fatal("IsGoBinary = false, want true")
	}
	if info.BinaryPath == "" {
		t.Fatal("BinaryPath = empty, want non-empty")
	}
	if filepath.Base(info.BinaryPath) == "" {
		t.Fatalf("BinaryPath = %q, want basename", info.BinaryPath)
	}
	if len(info.Symbols) == 0 {
		t.Fatal("Symbols = empty, want populated symbol set")
	}
	if got := info.GoVersion; !strings.HasPrefix(got, "go") {
		t.Fatalf("GoVersion = %q, want go version prefix", got)
	}
}

func buildGoTLSFixture(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	sourcePath := filepath.Join(tmpDir, "main.go")
	binaryPath := filepath.Join(tmpDir, "fixture")
	source := `package main

import (
	"crypto/tls"
	"net"
)

func main() {
	var conn tls.Conn
	_ = conn.ConnectionState()
	_ = conn.NetConn()
	_, _ = net.Pipe()
}
`

	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile(main.go) error = %v", err)
	}

	cmd := exec.Command("/usr/local/go/bin/go", "build", "-o", binaryPath, sourcePath)
	cmd.Env = append(os.Environ(), "PATH=/usr/local/go/bin:/usr/bin:/bin")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build error = %v, output = %s", err, output)
	}

	return binaryPath
}
