package fcktls

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ExeResolver interface {
	ResolveExe(pid int) (string, error)
}

type ProcessMatch struct {
	PID      int
	ExePath  string
	Basename string
}

type ProcessMonitor struct {
	target   string
	resolver ExeResolver
}

func NewProcessMonitor(target string, resolver ExeResolver) ProcessMonitor {
	if resolver == nil {
		resolver = procExeResolver{}
	}

	return ProcessMonitor{
		target:   filepath.Base(strings.TrimSpace(target)),
		resolver: resolver,
	}
}

func (m ProcessMonitor) MatchPID(pid int) (ProcessMatch, bool, error) {
	exePath, err := m.resolver.ResolveExe(pid)
	if err != nil {
		return ProcessMatch{}, false, err
	}

	match := ProcessMatch{
		PID:      pid,
		ExePath:  exePath,
		Basename: filepath.Base(exePath),
	}

	if !MatchTargetBasename(m.target, exePath) {
		return match, false, nil
	}

	return match, true, nil
}

type procExeResolver struct{}

func (procExeResolver) ResolveExe(pid int) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}
