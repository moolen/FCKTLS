package fcktls

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestArtifactWriterPersistsSessionArtifacts(t *testing.T) {
	root := t.TempDir()
	writer := NewArtifactWriter(root)
	verifyMode := 3
	sessionReused := true
	verifyResult := 0
	negotiatedGroup := 1034
	snapshot := SessionSnapshot{
		Metadata: SessionMetadata{
			SessionID:       "pid-77-ssl-0x7",
			Key:             SessionKey{PID: 77, SSLPointer: 0x7},
			PID:             77,
			ExePath:         "/usr/bin/curl",
			SocketFD:        intPtr(21),
			SNI:             "example.com",
			Groups:          "X25519:P-256",
			VerifyMode:      &verifyMode,
			SessionReused:   &sessionReused,
			VerifyResult:    &verifyResult,
			NegotiatedGroup: &negotiatedGroup,
			TLSVersion:      "TLSv1.3",
			CipherSuite:     "TLS_AES_128_GCM_SHA256",
			KeyStatus:       KeyStatusAvailable,
			KeyLogLines:     []string{"CLIENT_RANDOM abc def"},
			CaptureMode:     CaptureModeCapture,
			FirstSeen:       time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC),
			LastSeen:        time.Date(2026, 5, 9, 12, 0, 1, 0, time.UTC),
			Certificates:    []CertificateSummary{{Subject: "CN=example.com", Issuer: "CN=Example CA"}},
			KeyStatusNote:   "key log exported",
		},
		Streams: PlaintextStreams{
			ClientToServer: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			ServerToClient: []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
		},
	}

	paths, err := writer.WriteSession(snapshot)
	if err != nil {
		t.Fatalf("WriteSession() error = %v", err)
	}

	if _, err := os.Stat(paths.SummaryJSON); err != nil {
		t.Fatalf("summary.json stat error = %v", err)
	}

	if _, err := os.Stat(paths.KeysLog); err != nil {
		t.Fatalf("keys.log stat error = %v", err)
	}

	if _, err := os.Stat(paths.RequestText); err != nil {
		t.Fatalf("request.txt stat error = %v", err)
	}

	if _, err := os.Stat(paths.ResponseText); err != nil {
		t.Fatalf("response.txt stat error = %v", err)
	}

	if got, want := filepath.Base(filepath.Dir(paths.SummaryJSON)), snapshot.Metadata.SessionID; got != want {
		t.Fatalf("session directory = %q, want %q", got, want)
	}

	rawRequest, err := os.ReadFile(paths.ClientToServerBin)
	if err != nil {
		t.Fatalf("ReadFile(client) error = %v", err)
	}

	if string(rawRequest) != string(snapshot.Streams.ClientToServer) {
		t.Fatalf("client stream = %q, want %q", rawRequest, snapshot.Streams.ClientToServer)
	}

	requestText, err := os.ReadFile(paths.RequestText)
	if err != nil {
		t.Fatalf("ReadFile(request.txt) error = %v", err)
	}

	if !strings.Contains(string(requestText), "GET / HTTP/1.1") {
		t.Fatalf("request.txt = %q, want request line", requestText)
	}

	rawSummary, err := os.ReadFile(paths.SummaryJSON)
	if err != nil {
		t.Fatalf("ReadFile(summary.json) error = %v", err)
	}

	var summary struct {
		Metadata SessionMetadata `json:"metadata"`
	}
	if err := json.Unmarshal(rawSummary, &summary); err != nil {
		t.Fatalf("Unmarshal(summary.json) error = %v", err)
	}

	if summary.Metadata.SocketFD == nil || *summary.Metadata.SocketFD != 21 {
		t.Fatalf("summary socket_fd = %v, want 21", summary.Metadata.SocketFD)
	}
	if got, want := summary.Metadata.Groups, "X25519:P-256"; got != want {
		t.Fatalf("summary groups = %q, want %q", got, want)
	}
	if summary.Metadata.VerifyMode == nil || *summary.Metadata.VerifyMode != verifyMode {
		t.Fatalf("summary verify_mode = %v, want %d", summary.Metadata.VerifyMode, verifyMode)
	}
	if summary.Metadata.SessionReused == nil || *summary.Metadata.SessionReused != sessionReused {
		t.Fatalf("summary session_reused = %v, want %v", summary.Metadata.SessionReused, sessionReused)
	}
	if summary.Metadata.VerifyResult == nil || *summary.Metadata.VerifyResult != verifyResult {
		t.Fatalf("summary verify_result = %v, want %d", summary.Metadata.VerifyResult, verifyResult)
	}
	if summary.Metadata.NegotiatedGroup == nil || *summary.Metadata.NegotiatedGroup != negotiatedGroup {
		t.Fatalf("summary negotiated_group = %v, want %d", summary.Metadata.NegotiatedGroup, negotiatedGroup)
	}
}
