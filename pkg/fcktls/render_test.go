package fcktls

import (
	"strings"
	"testing"
)

func TestRenderSessionSummary(t *testing.T) {
	out := RenderSessionSummary(SessionSnapshot{
		Metadata: SessionMetadata{
			SessionID:   "pid-11-ssl-0xb",
			PID:         11,
			ExePath:     "/usr/bin/curl",
			SNI:         "example.com",
			TLSVersion:  "TLSv1.3",
			CipherSuite: "TLS_AES_128_GCM_SHA256",
			KeyStatus:   KeyStatusAvailable,
			CaptureMode: CaptureModeMetadataOnly,
			Source:      Endpoint{Address: "127.0.0.1", Port: 50000},
			Destination: Endpoint{Address: "93.184.216.34", Port: 443},
		},
	})

	for _, want := range []string{"pid-11-ssl-0xb", "pid=11", "curl", "example.com", "TLSv1.3", "available"} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing %q in %q", want, out)
		}
	}
}

func TestRenderCaptureOutput(t *testing.T) {
	out := RenderCapture(SessionSnapshot{
		Metadata: SessionMetadata{SessionID: "pid-11-ssl-0xb"},
		Streams: PlaintextStreams{
			ClientToServer: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			ServerToClient: []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
		},
	})

	for _, want := range []string{"client-to-server", "server-to-client", "GET / HTTP/1.1", "HTTP/1.1 200 OK"} {
		if !strings.Contains(out, want) {
			t.Fatalf("capture output missing %q in %q", want, out)
		}
	}
}

func TestRenderSessionSummaryIncludesObservedOpenSSLEventMetadataOnly(t *testing.T) {
	reused := false
	verifyResult := 0
	negotiatedGroup := 1034
	out := RenderSessionSummary(SessionSnapshot{
		Metadata: SessionMetadata{
			SessionID:       "pid-12-ssl-0xc",
			PID:             12,
			ExePath:         "/usr/bin/curl",
			SocketFD:        intPtr(17),
			SNI:             "example.com",
			Groups:          "X25519:P-256",
			VerifyMode:      intPtr(1),
			SessionReused:   &reused,
			VerifyResult:    &verifyResult,
			NegotiatedGroup: &negotiatedGroup,
			KeyStatus:       KeyStatusUnavailable,
			CaptureMode:     CaptureModeMetadataOnly,
		},
	})

	for _, want := range []string{
		"fd=17",
		"sni=example.com",
		"groups=X25519:P-256",
		"verify_mode=1",
		"session_reused=false",
		"verify_result=0",
		"negotiated_group=1034",
		"key_status=unavailable",
		"capture=metadata",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing %q in %q", want, out)
		}
	}

	for _, unwanted := range []string{"tls=", "cipher=", "alpn=", "certs="} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("summary unexpectedly contains %q in %q", unwanted, out)
		}
	}
}
