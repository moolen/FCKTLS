//go:build linux && amd64

package fcktls

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestE2ETLS12ClientRandomExport(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("linux/amd64 only")
	}
	if os.Getenv("FCKTLS_E2E") == "" {
		t.Skip("set FCKTLS_E2E=1 to run e2e test")
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for eBPF and ptrace integration")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 10; i++ {
			_, _ = io.WriteString(w, "tls12-ok\n")
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(100 * time.Millisecond)
		}
	}))
	server.EnableHTTP2 = false
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	defer server.Close()

	cacheRoot := t.TempDir()
	cfg, err := NewConfig("curl", true, cacheRoot)
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	daemon, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	daemon.Stdout = io.Discard

	ready := make(chan struct{})
	daemon.OnReady = func() { close(ready) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- daemon.Run(ctx)
	}()

	select {
	case <-ready:
	case err := <-runErrCh:
		t.Fatalf("daemon exited before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for daemon readiness")
	}

	curlOutputPath := filepath.Join(cacheRoot, "curl.out")
	curlErrorPath := filepath.Join(cacheRoot, "curl.err")
	curlStatusPath := filepath.Join(cacheRoot, "curl.status")
	curlPID, err := launchDetachedCommand(
		curlOutputPath,
		curlErrorPath,
		curlStatusPath,
		"curl",
		"--silent",
		"--show-error",
		"--insecure",
		"--http1.1",
		"--tls-max", "1.2",
		server.URL,
	)
	if err != nil {
		t.Fatalf("launchDetachedCommand() error = %v", err)
	}
	defer terminateDetachedProcessGroup(curlPID)

	result, err := waitForDetachedCommand(curlStatusPath, 15*time.Second)
	if err != nil {
		stdout, _ := os.ReadFile(curlOutputPath)
		stderr, _ := os.ReadFile(curlErrorPath)
		t.Fatalf("waitForDetachedCommand() error = %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if got, want := result.ExitCode, 0; got != want {
		stdout, _ := os.ReadFile(curlOutputPath)
		stderr, _ := os.ReadFile(curlErrorPath)
		t.Fatalf("curl exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", got, want, stdout, stderr)
	}

	output, err := os.ReadFile(curlOutputPath)
	if err != nil {
		t.Fatalf("ReadFile(curl.out) error = %v", err)
	}
	if !strings.Contains(string(output), "tls12-ok") {
		t.Fatalf("curl output = %q, want tls12-ok payload", output)
	}

	summaryPath, keysPath, err := waitForSessionFiles(cacheRoot, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	cancel()
	if err := <-runErrCh; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon.Run() error = %v", err)
	}

	rawSummary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("ReadFile(summary.json) error = %v", err)
	}

	var summary struct {
		Metadata SessionMetadata `json:"metadata"`
	}
	if err := json.Unmarshal(rawSummary, &summary); err != nil {
		t.Fatalf("Unmarshal(summary.json) error = %v", err)
	}

	if got, want := summary.Metadata.TLSVersion, "TLSv1.2"; got != want {
		t.Fatalf("TLSVersion = %q, want %q", got, want)
	}
	if summary.Metadata.CipherSuite == "" {
		t.Fatal("CipherSuite is empty")
	}
	if got, want := summary.Metadata.KeyStatus, KeyStatusAvailable; got != want {
		t.Fatalf("KeyStatus = %q, want %q", got, want)
	}

	rawKeys, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatalf("ReadFile(keys.log) error = %v", err)
	}
	if !strings.Contains(string(rawKeys), "CLIENT_RANDOM ") {
		t.Fatalf("keys.log = %q, want CLIENT_RANDOM entry", rawKeys)
	}
}

func TestE2ETLS13TrafficSecretExport(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("linux/amd64 only")
	}
	if os.Getenv("FCKTLS_E2E") == "" {
		t.Skip("set FCKTLS_E2E=1 to run e2e test")
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for eBPF and ptrace integration")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "tls13-ok\n")
	}))
	server.EnableHTTP2 = false
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	defer server.Close()

	cacheRoot := t.TempDir()
	cfg, err := NewConfig("curl", false, cacheRoot)
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	daemon, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	daemon.Stdout = io.Discard

	ready := make(chan struct{})
	daemon.OnReady = func() { close(ready) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- daemon.Run(ctx)
	}()

	select {
	case <-ready:
	case err := <-runErrCh:
		t.Fatalf("daemon exited before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for daemon readiness")
	}

	curlOutputPath := filepath.Join(cacheRoot, "curl.out")
	curlErrorPath := filepath.Join(cacheRoot, "curl.err")
	curlStatusPath := filepath.Join(cacheRoot, "curl.status")
	curlPID, err := launchDetachedCommand(
		curlOutputPath,
		curlErrorPath,
		curlStatusPath,
		"curl",
		"--silent",
		"--show-error",
		"--insecure",
		"--http1.1",
		server.URL,
	)
	if err != nil {
		t.Fatalf("launchDetachedCommand() error = %v", err)
	}
	defer terminateDetachedProcessGroup(curlPID)

	result, err := waitForDetachedCommand(curlStatusPath, 15*time.Second)
	if err != nil {
		stdout, _ := os.ReadFile(curlOutputPath)
		stderr, _ := os.ReadFile(curlErrorPath)
		t.Fatalf("waitForDetachedCommand() error = %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if got, want := result.ExitCode, 0; got != want {
		stdout, _ := os.ReadFile(curlOutputPath)
		stderr, _ := os.ReadFile(curlErrorPath)
		t.Fatalf("curl exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", got, want, stdout, stderr)
	}

	summaryPath, keysPath, err := waitForSessionFiles(cacheRoot, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	cancel()
	if err := <-runErrCh; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon.Run() error = %v", err)
	}

	rawSummary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("ReadFile(summary.json) error = %v", err)
	}

	var summary struct {
		Metadata SessionMetadata `json:"metadata"`
	}
	if err := json.Unmarshal(rawSummary, &summary); err != nil {
		t.Fatalf("Unmarshal(summary.json) error = %v", err)
	}
	if got, want := summary.Metadata.TLSVersion, "TLSv1.3"; got != want {
		t.Fatalf("TLSVersion = %q, want %q", got, want)
	}
	if got, want := summary.Metadata.KeyStatus, KeyStatusAvailable; got != want {
		t.Fatalf("KeyStatus = %q, want %q", got, want)
	}

	rawKeys, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatalf("ReadFile(keys.log) error = %v", err)
	}
	keyText := string(rawKeys)
	if !strings.Contains(keyText, "CLIENT_TRAFFIC_SECRET_0 ") &&
		!strings.Contains(keyText, "SERVER_TRAFFIC_SECRET_0 ") &&
		!strings.Contains(keyText, "CLIENT_HANDSHAKE_TRAFFIC_SECRET ") &&
		!strings.Contains(keyText, "SERVER_HANDSHAKE_TRAFFIC_SECRET ") {
		t.Fatalf("keys.log = %q, want TLS 1.3 traffic secret entry", rawKeys)
	}
}

func TestE2EGnuTLSCLIPlaintextCapture(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("linux/amd64 only")
	}
	if os.Getenv("FCKTLS_E2E") == "" {
		t.Skip("set FCKTLS_E2E=1 to run e2e test")
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for eBPF integration")
	}
	if _, err := exec.LookPath("gnutls-cli"); err != nil {
		t.Skip("gnutls-cli not installed")
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "gnutls-ok\n")
	}))
	defer server.Close()

	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatalf("SplitHostPort(server.URL) error = %v", err)
	}

	cacheRoot := t.TempDir()
	cfg, err := NewConfig("gnutls-cli", true, cacheRoot)
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	daemon, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	daemon.Stdout = io.Discard

	ready := make(chan struct{})
	daemon.OnReady = func() { close(ready) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- daemon.Run(ctx)
	}()

	select {
	case <-ready:
	case err := <-runErrCh:
		t.Fatalf("daemon exited before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for daemon readiness")
	}

	clientOutputPath := filepath.Join(cacheRoot, "gnutls-cli.out")
	clientErrorPath := filepath.Join(cacheRoot, "gnutls-cli.err")
	clientStatusPath := filepath.Join(cacheRoot, "gnutls-cli.status")
	clientPID, err := launchDetachedCommand(
		clientOutputPath,
		clientErrorPath,
		clientStatusPath,
		"sh",
		"-c",
		"printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' \"$1\" | gnutls-cli --insecure -p \"$2\" \"$1\"",
		"gnutls-cli-e2e",
		"localhost",
		port,
	)
	if err != nil {
		t.Fatalf("launchDetachedCommand() error = %v", err)
	}
	defer terminateDetachedProcessGroup(clientPID)

	result, err := waitForDetachedCommand(clientStatusPath, 15*time.Second)
	if err != nil {
		stdout, _ := os.ReadFile(clientOutputPath)
		stderr, _ := os.ReadFile(clientErrorPath)
		t.Fatalf("waitForDetachedCommand() error = %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if got, want := result.ExitCode, 0; got != want {
		stdout, _ := os.ReadFile(clientOutputPath)
		stderr, _ := os.ReadFile(clientErrorPath)
		t.Fatalf("gnutls-cli exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", got, want, stdout, stderr)
	}

	output, err := os.ReadFile(clientOutputPath)
	if err != nil {
		t.Fatalf("ReadFile(gnutls-cli.out) error = %v", err)
	}
	if !strings.Contains(string(output), "gnutls-ok") {
		t.Fatalf("gnutls-cli output = %q, want response body", output)
	}

	sessionDir, summaryPath, err := waitForSessionSummary(cacheRoot, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	cancel()
	if err := <-runErrCh; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon.Run() error = %v", err)
	}

	rawSummary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("ReadFile(summary.json) error = %v", err)
	}

	var summary struct {
		Metadata SessionMetadata `json:"metadata"`
	}
	if err := json.Unmarshal(rawSummary, &summary); err != nil {
		t.Fatalf("Unmarshal(summary.json) error = %v", err)
	}

	if !strings.HasSuffix(summary.Metadata.ExePath, "/gnutls-cli") {
		t.Fatalf("ExePath = %q, want gnutls-cli", summary.Metadata.ExePath)
	}
	if !strings.Contains(summary.Metadata.LibraryPath, "libgnutls.so") {
		t.Fatalf("LibraryPath = %q, want libgnutls.so", summary.Metadata.LibraryPath)
	}
	if got, want := summary.Metadata.CaptureMode, CaptureModeCapture; got != want {
		t.Fatalf("CaptureMode = %q, want %q", got, want)
	}

	requestPath := filepath.Join(sessionDir, "request.txt")
	request, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatalf("ReadFile(request.txt) error = %v", err)
	}
	if !strings.Contains(string(request), "GET / HTTP/1.1") {
		t.Fatalf("request.txt = %q, want HTTP request", request)
	}

	responsePath := filepath.Join(sessionDir, "response.txt")
	response, err := os.ReadFile(responsePath)
	if err != nil {
		t.Fatalf("ReadFile(response.txt) error = %v", err)
	}
	if !strings.Contains(string(response), "HTTP/1.1 200 OK") || !strings.Contains(string(response), "gnutls-ok") {
		t.Fatalf("response.txt = %q, want HTTP response", response)
	}
}

func TestE2EGoTLSClientStopOnExecAttach(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("linux/amd64 only")
	}
	if os.Getenv("FCKTLS_E2E") == "" {
		t.Skip("set FCKTLS_E2E=1 to run e2e test")
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for eBPF and ptrace integration")
	}

	clientPath := buildGoTLSE2EClient(t)
	targetName := filepath.Base(clientPath)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "go-tls-ok\n")
	}))
	server.EnableHTTP2 = false
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	defer server.Close()

	cacheRoot := t.TempDir()
	cfg, err := NewConfig(targetName, true, cacheRoot)
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	daemon, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	daemon.Stdout = io.Discard

	ready := make(chan struct{})
	daemon.OnReady = func() { close(ready) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- daemon.Run(ctx)
	}()

	select {
	case <-ready:
	case err := <-runErrCh:
		t.Fatalf("daemon exited before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for daemon readiness")
	}

	clientOutputPath := filepath.Join(cacheRoot, targetName+".out")
	clientErrorPath := filepath.Join(cacheRoot, targetName+".err")
	clientStatusPath := filepath.Join(cacheRoot, targetName+".status")
	clientPID, err := launchDetachedCommand(
		clientOutputPath,
		clientErrorPath,
		clientStatusPath,
		clientPath,
		server.URL,
	)
	if err != nil {
		t.Fatalf("launchDetachedCommand() error = %v", err)
	}
	defer terminateDetachedProcessGroup(clientPID)

	result, err := waitForDetachedCommand(clientStatusPath, 15*time.Second)
	if err != nil {
		stdout, _ := os.ReadFile(clientOutputPath)
		stderr, _ := os.ReadFile(clientErrorPath)
		t.Fatalf("waitForDetachedCommand() error = %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if got, want := result.ExitCode, 0; got != want {
		stdout, _ := os.ReadFile(clientOutputPath)
		stderr, _ := os.ReadFile(clientErrorPath)
		t.Fatalf("go tls client exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", got, want, stdout, stderr)
	}

	output, err := os.ReadFile(clientOutputPath)
	if err != nil {
		t.Fatalf("ReadFile(client.out) error = %v", err)
	}
	if !strings.Contains(string(output), "go-tls-ok") {
		t.Fatalf("client output = %q, want response body", output)
	}

	sessionDir, summaryPath, err := waitForSessionSummary(cacheRoot, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	cancel()
	if err := <-runErrCh; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon.Run() error = %v", err)
	}

	rawSummary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("ReadFile(summary.json) error = %v", err)
	}

	var summary struct {
		Metadata SessionMetadata `json:"metadata"`
	}
	if err := json.Unmarshal(rawSummary, &summary); err != nil {
		t.Fatalf("Unmarshal(summary.json) error = %v", err)
	}

	if got, want := filepath.Base(summary.Metadata.ExePath), targetName; got != want {
		t.Fatalf("ExePath basename = %q, want %q", got, want)
	}
	if got, want := summary.Metadata.Role, "client"; got != want {
		t.Fatalf("Role = %q, want %q", got, want)
	}
	if strings.TrimSpace(summary.Metadata.TLSVersion) == "" {
		t.Fatal("TLSVersion is empty")
	}
	if strings.TrimSpace(summary.Metadata.CipherSuite) == "" {
		t.Fatal("CipherSuite is empty")
	}
	if got, want := summary.Metadata.KeyStatus, KeyStatusUnavailable; got != want {
		t.Fatalf("KeyStatus = %q, want %q", got, want)
	}
	if got := summary.Metadata.KeyStatusNote; !strings.Contains(got, "go key export not implemented") {
		t.Fatalf("KeyStatusNote = %q, want go key export not implemented", got)
	}
	if got, want := summary.Metadata.CaptureMode, CaptureModeCapture; got != want {
		t.Fatalf("CaptureMode = %q, want %q", got, want)
	}

	requestPath := filepath.Join(sessionDir, "request.txt")
	request, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatalf("ReadFile(request.txt) error = %v", err)
	}
	serverTarget, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse(server.URL) error = %v", err)
	}
	if !strings.Contains(string(request), "GET / HTTP/1.1") || !strings.Contains(string(request), "Host: "+serverTarget.Hostname()) {
		t.Fatalf("request.txt = %q, want HTTP request", request)
	}

	responsePath := filepath.Join(sessionDir, "response.txt")
	response, err := os.ReadFile(responsePath)
	if err != nil {
		t.Fatalf("ReadFile(response.txt) error = %v", err)
	}
	if !strings.Contains(string(response), "HTTP/1.1 200 OK") || !strings.Contains(string(response), "go-tls-ok") {
		t.Fatalf("response.txt = %q, want HTTP response", response)
	}
}

func buildGoTLSE2EClient(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	sourcePath := filepath.Join(tmpDir, "main.go")
	binaryPath := filepath.Join(tmpDir, "go-tls-client-e2e")
	source := `package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go-tls-client-e2e <url>")
		os.Exit(2)
	}

	time.Sleep(250 * time.Millisecond)

	target, err := url.Parse(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	conn, err := tls.Dial("tcp", target.Host, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
		ServerName:         "localhost",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	host := target.Hostname()
	if host == "" {
		host = "localhost"
	}
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target.RequestURI(), host); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("tls=%x cipher=%x\n", state.Version, state.CipherSuite)
	fmt.Print(string(body))
}
`

	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile(main.go) error = %v", err)
	}

	goBinary := "go"
	if _, err := exec.LookPath(goBinary); err != nil {
		const fallback = "/usr/local/go/bin/go"
		if _, statErr := os.Stat(fallback); statErr != nil {
			t.Fatalf("go tool not found in PATH and fallback %s unavailable: %v", fallback, err)
		}
		goBinary = fallback
	}

	cmd := exec.Command(goBinary, "build", "-o", binaryPath, sourcePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build error = %v, output = %s", err, output)
	}

	return binaryPath
}

func waitForSessionFiles(cacheRoot string, timeout time.Duration) (string, string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(cacheRoot)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				dir := filepath.Join(cacheRoot, entry.Name())
				summaryPath := filepath.Join(dir, "summary.json")
				keysPath := filepath.Join(dir, "keys.log")
				if _, err := os.Stat(summaryPath); err != nil {
					continue
				}
				if _, err := os.Stat(keysPath); err != nil {
					continue
				}
				return summaryPath, keysPath, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", "", errors.New("timed out waiting for session summary and keys")
}

func waitForSessionSummary(cacheRoot string, timeout time.Duration) (string, string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(cacheRoot)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				dir := filepath.Join(cacheRoot, entry.Name())
				summaryPath := filepath.Join(dir, "summary.json")
				if _, err := os.Stat(summaryPath); err != nil {
					continue
				}
				return dir, summaryPath, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", "", errors.New("timed out waiting for session summary")
}
