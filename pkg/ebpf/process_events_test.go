package ebpf

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestDecodeProcessEvent(t *testing.T) {
	t.Parallel()

	raw := make([]byte, processEventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 123456789)
	binary.LittleEndian.PutUint32(raw[8:12], 101)
	binary.LittleEndian.PutUint32(raw[12:16], 202)
	raw[16] = byte(ProcessEventTypeExec)

	event, err := decodeProcessEvent(raw)
	if err != nil {
		t.Fatalf("decodeProcessEvent returned error: %v", err)
	}
	if event.TimestampNS != 123456789 {
		t.Fatalf("TimestampNS = %d, want 123456789", event.TimestampNS)
	}
	if event.PID != 101 {
		t.Fatalf("PID = %d, want 101", event.PID)
	}
	if event.TID != 202 {
		t.Fatalf("TID = %d, want 202", event.TID)
	}
	if event.EventType != ProcessEventTypeExec {
		t.Fatalf("EventType = %d, want %d", event.EventType, ProcessEventTypeExec)
	}
}

func TestCandidateNamedObjectPaths(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	objectName := "openssl_uprobe_bpfel.o"
	cwdObject := filepath.Join(tmpDir, objectName)
	pkgObject := filepath.Join(tmpDir, "pkg", "ebpf", objectName)
	if err := os.MkdirAll(filepath.Dir(pkgObject), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(cwdObject, []byte("a"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", cwdObject, err)
	}
	if err := os.WriteFile(pkgObject, []byte("b"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", pkgObject, err)
	}

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	t.Cleanup(func() {
		if chdirErr := os.Chdir(origWD); chdirErr != nil {
			t.Fatalf("restore cwd: %v", chdirErr)
		}
	})
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir(%q): %v", tmpDir, err)
	}

	paths := candidateNamedObjectPaths(objectName)
	if len(paths) < 2 {
		t.Fatalf("len(paths) = %d, want at least 2 (%v)", len(paths), paths)
	}
	if paths[0] != objectName {
		t.Fatalf("paths[0] = %q, want %q", paths[0], objectName)
	}
	if paths[1] != filepath.Join("pkg", "ebpf", objectName) {
		t.Fatalf("paths[1] = %q, want %q", paths[1], filepath.Join("pkg", "ebpf", objectName))
	}
}
