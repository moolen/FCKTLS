package fcktls

import (
	"path/filepath"
	"testing"
)

func TestNewConfigDefaults(t *testing.T) {
	cfg, err := NewConfig("/usr/bin/curl", false, "")
	if err != nil {
		t.Fatalf("NewConfig() error = %v", err)
	}

	if cfg.Target != "curl" {
		t.Fatalf("Target = %q, want %q", cfg.Target, "curl")
	}

	if cfg.CaptureMode != CaptureModeMetadataOnly {
		t.Fatalf("CaptureMode = %q, want %q", cfg.CaptureMode, CaptureModeMetadataOnly)
	}

	if got, want := filepath.Base(cfg.CacheRoot), "fcktls"; got != want {
		t.Fatalf("CacheRoot basename = %q, want %q", got, want)
	}
}

func TestSessionKeyString(t *testing.T) {
	key := SessionKey{PID: 42, SSLPointer: 0x1234}

	if got, want := key.String(), "pid-42-ssl-0x1234"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestKeyStatusString(t *testing.T) {
	if got, want := KeyStatusAvailable.String(), "available"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
