//go:build linux && amd64

package fcktls

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
