//go:build linux && amd64

package fcktls

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLaunchDetachedCommandWritesOutputAndExitStatus(t *testing.T) {
	dir := t.TempDir()
	stdoutPath := filepath.Join(dir, "stdout.txt")
	stderrPath := filepath.Join(dir, "stderr.txt")
	statusPath := filepath.Join(dir, "status.txt")

	pid, err := launchDetachedCommand(
		stdoutPath,
		stderrPath,
		statusPath,
		"sh",
		"-c",
		"printf 'hello\\n'; printf 'warn\\n' >&2; exit 7",
	)
	if err != nil {
		t.Fatalf("launchDetachedCommand() error = %v", err)
	}
	if pid <= 0 {
		t.Fatalf("pid = %d, want positive pid", pid)
	}

	result, err := waitForDetachedCommand(statusPath, 5*time.Second)
	if err != nil {
		t.Fatalf("waitForDetachedCommand() error = %v", err)
	}
	if got, want := result.ExitCode, 7; got != want {
		t.Fatalf("ExitCode = %d, want %d", got, want)
	}

	stdout, err := os.ReadFile(stdoutPath)
	if err != nil {
		t.Fatalf("ReadFile(stdout) error = %v", err)
	}
	if got, want := string(stdout), "hello\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}

	stderr, err := os.ReadFile(stderrPath)
	if err != nil {
		t.Fatalf("ReadFile(stderr) error = %v", err)
	}
	if got, want := string(stderr), "warn\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestWaitForDetachedCommandRejectsMalformedStatus(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "status.txt")
	if err := os.WriteFile(statusPath, []byte("bogus"), 0o644); err != nil {
		t.Fatalf("WriteFile(status) error = %v", err)
	}

	_, err := waitForDetachedCommand(statusPath, time.Second)
	if err == nil {
		t.Fatal("waitForDetachedCommand() error = nil, want parse failure")
	}
	if !strings.Contains(err.Error(), "parse exit status") {
		t.Fatalf("error = %v, want parse exit status", err)
	}
}

type detachedCommandResult struct {
	ExitCode int
}

func launchDetachedCommand(stdoutPath string, stderrPath string, statusPath string, name string, args ...string) (int, error) {
	for _, path := range []string{stdoutPath, stderrPath, statusPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return 0, fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
		}
	}

	scriptPath := filepath.Join(filepath.Dir(statusPath), "launch_detached_command.sh")
	script := strings.Join([]string{
		"#!/bin/sh",
		"\"$@\" >\"$FCKTLS_STDOUT_PATH\" 2>\"$FCKTLS_STDERR_PATH\"",
		"rc=$?",
		"tmp=\"$FCKTLS_STATUS_PATH.tmp.$$\"",
		"printf '%s\\n' \"$rc\" >\"$tmp\"",
		"mv \"$tmp\" \"$FCKTLS_STATUS_PATH\"",
		"",
	}, "\n")
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		return 0, fmt.Errorf("write launcher script: %w", err)
	}

	launcherArgs := append([]string{"-c", "setsid sh \"$@\" >/dev/null 2>&1 < /dev/null & echo $!", "launchDetachedCommand", scriptPath, name}, args...)
	cmd := exec.Command("sh", launcherArgs...)
	cmd.Env = append(
		os.Environ(),
		"FCKTLS_STDOUT_PATH="+stdoutPath,
		"FCKTLS_STDERR_PATH="+stderrPath,
		"FCKTLS_STATUS_PATH="+statusPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("launch detached command: %w (%s)", err, strings.TrimSpace(string(output)))
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		return 0, fmt.Errorf("parse detached pid: %w", err)
	}

	return pid, nil
}

func waitForDetachedCommand(statusPath string, timeout time.Duration) (detachedCommandResult, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(statusPath)
		if err == nil {
			exitCode, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
			if parseErr != nil {
				return detachedCommandResult{}, fmt.Errorf("parse exit status: %w", parseErr)
			}
			return detachedCommandResult{ExitCode: exitCode}, nil
		}
		if !os.IsNotExist(err) {
			return detachedCommandResult{}, fmt.Errorf("read exit status: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	return detachedCommandResult{}, fmt.Errorf("timed out waiting for detached command status %s", statusPath)
}

func terminateDetachedProcessGroup(pid int) {
	if pid <= 0 {
		return
	}
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	time.Sleep(100 * time.Millisecond)
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
