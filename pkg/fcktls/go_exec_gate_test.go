package fcktls

import (
	"errors"
	"reflect"
	"testing"
)

func TestGoExecGateStopsAttachesAndResumesSupportedProcess(t *testing.T) {
	var calls []string
	loader := &stubGoTLSAttachLoader{
		attachProcess: func(pid int, executablePath string) error {
			calls = append(calls, "attach:"+executablePath)
			if got, want := pid, 4242; got != want {
				t.Fatalf("AttachProcess pid = %d, want %d", got, want)
			}
			return nil
		},
	}
	gate := &GoExecGate{
		Loader: loader,
		StopProcess: func(pid int) error {
			calls = append(calls, "stop")
			if got, want := pid, 4242; got != want {
				t.Fatalf("StopProcess pid = %d, want %d", got, want)
			}
			return nil
		},
		ResumeProcess: func(pid int) error {
			calls = append(calls, "resume")
			if got, want := pid, 4242; got != want {
				t.Fatalf("ResumeProcess pid = %d, want %d", got, want)
			}
			return nil
		},
		Inspect: func(path string) (goBinaryInspection, error) {
			calls = append(calls, "inspect:"+path)
			return goBinaryInspection{
				IsGoBinary: true,
				BinaryPath: "/opt/bin/go-client",
				Symbols: map[string]struct{}{
					goTLSClientHandshakeSymbol: {},
					goTLSConnectionStateSymbol: {},
				},
			}, nil
		},
	}

	attached, err := gate.HandleMatch(ProcessMatch{PID: 4242, ExePath: "/proc/4242/exe", Basename: "go-client"})
	if err != nil {
		t.Fatalf("HandleMatch() error = %v", err)
	}
	if !attached {
		t.Fatal("HandleMatch() attached = false, want true")
	}

	if got, want := calls, []string{
		"inspect:/proc/4242/exe",
		"stop",
		"attach:/opt/bin/go-client",
		"resume",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("call order = %#v, want %#v", got, want)
	}
}

func TestGoExecGateResumesProcessWhenAttachFails(t *testing.T) {
	var calls []string
	loader := &stubGoTLSAttachLoader{
		attachProcess: func(pid int, executablePath string) error {
			calls = append(calls, "attach")
			return errors.New("attach failed")
		},
	}
	gate := &GoExecGate{
		Loader: loader,
		StopProcess: func(pid int) error {
			calls = append(calls, "stop")
			return nil
		},
		ResumeProcess: func(pid int) error {
			calls = append(calls, "resume")
			return nil
		},
		Inspect: func(path string) (goBinaryInspection, error) {
			calls = append(calls, "inspect")
			return goBinaryInspection{
				IsGoBinary: true,
				Symbols: map[string]struct{}{
					goTLSClientHandshakeSymbol: {},
					goTLSConnectionStateSymbol: {},
				},
			}, nil
		},
	}

	attached, err := gate.HandleMatch(ProcessMatch{PID: 5151, ExePath: "/usr/bin/go-client", Basename: "go-client"})
	if err == nil {
		t.Fatal("HandleMatch() error = nil, want attach failure")
	}
	if attached {
		t.Fatal("HandleMatch() attached = true, want false")
	}
	if got, want := calls, []string{"inspect", "stop", "attach", "resume"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("call order = %#v, want %#v", got, want)
	}
}

type stubGoTLSAttachLoader struct {
	attachProcess func(pid int, executablePath string) error
}

func (s *stubGoTLSAttachLoader) AttachProcess(pid int, executablePath string) error {
	return s.attachProcess(pid, executablePath)
}
