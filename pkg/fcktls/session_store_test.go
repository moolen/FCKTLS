package fcktls

import (
	"bytes"
	"testing"
	"time"
)

func TestSessionStoreMergesMetadataAndPlaintext(t *testing.T) {
	store := NewSessionStore()
	key := SessionKey{PID: 99, SSLPointer: 0xabc}
	firstSeen := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	lastSeen := firstSeen.Add(2 * time.Second)
	verifyMode := 3
	sessionReused := false
	verifyResult := 0
	negotiatedGroup := 1034

	store.MergeMetadata(SessionMetadataUpdate{
		Key:         key,
		ObservedAt:  firstSeen,
		ExePath:     "/usr/bin/curl",
		SNI:         "example.com",
		SocketFD:    intPtr(19),
		VerifyMode:  &verifyMode,
		Groups:      "X25519:P-256",
		TLSVersion:  "TLSv1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		KeyStatus:   KeyStatusPartial,
		CaptureMode: CaptureModeCapture,
	})

	store.MergeMetadata(SessionMetadataUpdate{
		Key:             key,
		ObservedAt:      lastSeen,
		ALPN:            "h2",
		SessionReused:   &sessionReused,
		VerifyResult:    &verifyResult,
		NegotiatedGroup: &negotiatedGroup,
		KeyStatus:       KeyStatusAvailable,
		KeyLogLines:     []string{"CLIENT_RANDOM abc def"},
		Certificates:    []CertificateSummary{{Subject: "CN=example.com", Issuer: "CN=Example CA"}},
		KeyStatusNote:   "key log exported",
	})

	store.AppendChunk(PlaintextChunk{
		Key:        key,
		Direction:  StreamDirectionClientToServer,
		ObservedAt: firstSeen.Add(500 * time.Millisecond),
		Data:       []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	store.AppendChunk(PlaintextChunk{
		Key:        key,
		Direction:  StreamDirectionServerToClient,
		ObservedAt: firstSeen.Add(time.Second),
		Data:       []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
	})

	snapshot, ok := store.Finalize(key, lastSeen)
	if !ok {
		t.Fatal("Finalize() ok = false, want true")
	}

	if got, want := snapshot.Metadata.SessionID, key.String(); got != want {
		t.Fatalf("SessionID = %q, want %q", got, want)
	}

	if got, want := snapshot.Metadata.FirstSeen, firstSeen; !got.Equal(want) {
		t.Fatalf("FirstSeen = %v, want %v", got, want)
	}

	if got, want := snapshot.Metadata.LastSeen, lastSeen; !got.Equal(want) {
		t.Fatalf("LastSeen = %v, want %v", got, want)
	}

	if got, want := snapshot.Metadata.KeyStatus, KeyStatusAvailable; got != want {
		t.Fatalf("KeyStatus = %q, want %q", got, want)
	}

	if got, want := snapshot.Metadata.ALPN, "h2"; got != want {
		t.Fatalf("ALPN = %q, want %q", got, want)
	}

	if snapshot.Metadata.SocketFD == nil || *snapshot.Metadata.SocketFD != 19 {
		t.Fatalf("SocketFD = %v, want 19", snapshot.Metadata.SocketFD)
	}

	if snapshot.Metadata.VerifyMode == nil || *snapshot.Metadata.VerifyMode != verifyMode {
		t.Fatalf("VerifyMode = %v, want %d", snapshot.Metadata.VerifyMode, verifyMode)
	}

	if got, want := snapshot.Metadata.Groups, "X25519:P-256"; got != want {
		t.Fatalf("Groups = %q, want %q", got, want)
	}

	if snapshot.Metadata.SessionReused == nil || *snapshot.Metadata.SessionReused != sessionReused {
		t.Fatalf("SessionReused = %v, want %v", snapshot.Metadata.SessionReused, sessionReused)
	}

	if snapshot.Metadata.VerifyResult == nil || *snapshot.Metadata.VerifyResult != verifyResult {
		t.Fatalf("VerifyResult = %v, want %d", snapshot.Metadata.VerifyResult, verifyResult)
	}

	if snapshot.Metadata.NegotiatedGroup == nil || *snapshot.Metadata.NegotiatedGroup != negotiatedGroup {
		t.Fatalf("NegotiatedGroup = %v, want %d", snapshot.Metadata.NegotiatedGroup, negotiatedGroup)
	}

	if got, want := len(snapshot.Metadata.Certificates), 1; got != want {
		t.Fatalf("Certificates len = %d, want %d", got, want)
	}

	if !bytes.Equal(snapshot.Streams.ClientToServer, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")) {
		t.Fatalf("ClientToServer = %q", snapshot.Streams.ClientToServer)
	}

	if !bytes.Equal(snapshot.Streams.ServerToClient, []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")) {
		t.Fatalf("ServerToClient = %q", snapshot.Streams.ServerToClient)
	}
}

func TestSessionStoreFinalizeUnknownSession(t *testing.T) {
	store := NewSessionStore()

	if _, ok := store.Finalize(SessionKey{PID: 1, SSLPointer: 2}, time.Now()); ok {
		t.Fatal("Finalize() ok = true, want false")
	}
}

func intPtr(v int) *int {
	return &v
}
