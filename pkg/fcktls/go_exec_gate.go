package fcktls

import (
	"fmt"
	"syscall"
)

type goTLSAttachLoader interface {
	AttachProcess(pid int, executablePath string) error
}

type GoExecGate struct {
	Loader        goTLSAttachLoader
	Inspect       func(path string) (goBinaryInspection, error)
	StopProcess   func(pid int) error
	ResumeProcess func(pid int) error
}

func NewGoExecGate(loader goTLSAttachLoader) *GoExecGate {
	return &GoExecGate{
		Loader:        loader,
		Inspect:       InspectGoBinary,
		StopProcess:   stopProcess,
		ResumeProcess: resumeProcess,
	}
}

func (g *GoExecGate) HandleMatch(match ProcessMatch) (attached bool, err error) {
	if g == nil || g.Loader == nil || g.Inspect == nil {
		return false, nil
	}

	inspection, err := g.Inspect(match.ExePath)
	if err != nil {
		return false, err
	}
	if !inspection.SupportsCryptoTLS() {
		return false, nil
	}

	if g.StopProcess == nil {
		g.StopProcess = stopProcess
	}
	if g.ResumeProcess == nil {
		g.ResumeProcess = resumeProcess
	}

	if err := g.StopProcess(match.PID); err != nil {
		return false, fmt.Errorf("stop pid %d: %w", match.PID, err)
	}
	defer func() {
		resumeErr := g.ResumeProcess(match.PID)
		if err == nil && resumeErr != nil {
			err = fmt.Errorf("resume pid %d: %w", match.PID, resumeErr)
		}
	}()

	executablePath := match.ExePath
	if inspection.BinaryPath != "" {
		executablePath = inspection.BinaryPath
	}
	if err := g.Loader.AttachProcess(match.PID, executablePath); err != nil {
		return false, fmt.Errorf("attach go tls pid %d: %w", match.PID, err)
	}

	return true, nil
}

func stopProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGSTOP)
}

func resumeProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGCONT)
}
