package fcktls

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Target      string
	CaptureMode CaptureMode
	CacheRoot   string
}

func DefaultConfig() Config {
	return Config{
		CaptureMode: CaptureModeMetadataOnly,
		CacheRoot:   defaultCacheRoot(),
	}
}

func NewConfig(target string, capture bool, cacheRoot string) (Config, error) {
	target = filepath.Base(strings.TrimSpace(target))
	if target == "" {
		return Config{}, errors.New("target is required")
	}

	cfg := DefaultConfig()
	cfg.Target = target
	if capture {
		cfg.CaptureMode = CaptureModeCapture
	}
	if strings.TrimSpace(cacheRoot) != "" {
		cfg.CacheRoot = cacheRoot
	}

	return cfg, nil
}

func MatchTargetBasename(target string, exePath string) bool {
	target = filepath.Base(strings.TrimSpace(target))
	exePath = strings.TrimSpace(exePath)
	if target == "" || exePath == "" {
		return false
	}

	return filepath.Base(exePath) == target
}

func defaultCacheRoot() string {
	if dir, err := os.UserCacheDir(); err == nil && dir != "" {
		return filepath.Join(dir, "fcktls")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".cache", "fcktls")
	}

	return filepath.Join(".cache", "fcktls")
}
