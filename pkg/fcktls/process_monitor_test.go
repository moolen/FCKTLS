package fcktls

import (
	"errors"
	"testing"
)

func TestProcessMonitorMatchesResolvedBasename(t *testing.T) {
	monitor := NewProcessMonitor("curl", staticExeResolver{
		paths: map[int]string{1001: "/usr/bin/curl"},
	})

	match, ok, err := monitor.MatchPID(1001)
	if err != nil {
		t.Fatalf("MatchPID() error = %v", err)
	}

	if !ok {
		t.Fatal("MatchPID() ok = false, want true")
	}

	if match.ExePath != "/usr/bin/curl" {
		t.Fatalf("ExePath = %q, want %q", match.ExePath, "/usr/bin/curl")
	}
}

func TestProcessMonitorRejectsOtherBasenames(t *testing.T) {
	monitor := NewProcessMonitor("curl", staticExeResolver{
		paths: map[int]string{1002: "/usr/bin/wget"},
	})

	_, ok, err := monitor.MatchPID(1002)
	if err != nil {
		t.Fatalf("MatchPID() error = %v", err)
	}

	if ok {
		t.Fatal("MatchPID() ok = true, want false")
	}
}

func TestProcessMonitorReturnsResolverErrors(t *testing.T) {
	wantErr := errors.New("boom")
	monitor := NewProcessMonitor("curl", staticExeResolver{
		errs: map[int]error{1003: wantErr},
	})

	_, _, err := monitor.MatchPID(1003)
	if !errors.Is(err, wantErr) {
		t.Fatalf("MatchPID() error = %v, want %v", err, wantErr)
	}
}

type staticExeResolver struct {
	paths map[int]string
	errs  map[int]error
}

func (r staticExeResolver) ResolveExe(pid int) (string, error) {
	if err := r.errs[pid]; err != nil {
		return "", err
	}

	return r.paths[pid], nil
}
