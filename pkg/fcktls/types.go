package fcktls

import (
	"fmt"
	"time"
)

type CaptureMode string

const (
	CaptureModeMetadataOnly CaptureMode = "metadata"
	CaptureModeCapture      CaptureMode = "capture"
)

func (m CaptureMode) String() string {
	if m == "" {
		return string(CaptureModeMetadataOnly)
	}

	return string(m)
}

type KeyStatus string

const (
	KeyStatusUnknown     KeyStatus = "unknown"
	KeyStatusAvailable   KeyStatus = "available"
	KeyStatusUnavailable KeyStatus = "unavailable"
	KeyStatusPartial     KeyStatus = "partial"
	KeyStatusError       KeyStatus = "error"
)

func (s KeyStatus) String() string {
	if s == "" {
		return string(KeyStatusUnknown)
	}

	return string(s)
}

type StreamDirection string

const (
	StreamDirectionClientToServer StreamDirection = "client-to-server"
	StreamDirectionServerToClient StreamDirection = "server-to-client"
)

func (d StreamDirection) String() string {
	return string(d)
}

type SessionKey struct {
	PID        int
	SSLPointer uint64
}

func (k SessionKey) String() string {
	return fmt.Sprintf("pid-%d-ssl-0x%x", k.PID, k.SSLPointer)
}

type Endpoint struct {
	Address string `json:"address,omitempty"`
	Port    uint16 `json:"port,omitempty"`
}

func (e Endpoint) String() string {
	if e.Address == "" && e.Port == 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", e.Address, e.Port)
}

type CertificateSummary struct {
	Subject string `json:"subject,omitempty"`
	Issuer  string `json:"issuer,omitempty"`
}

type SessionMetadata struct {
	SessionID       string               `json:"session_id"`
	Key             SessionKey           `json:"key"`
	PID             int                  `json:"pid"`
	ExePath         string               `json:"exe_path,omitempty"`
	LibraryPath     string               `json:"library_path,omitempty"`
	Source          Endpoint             `json:"source,omitempty"`
	Destination     Endpoint             `json:"destination,omitempty"`
	Role            string               `json:"role,omitempty"`
	SocketFD        *int                 `json:"socket_fd,omitempty"`
	SNI             string               `json:"sni,omitempty"`
	Priority        string               `json:"priority,omitempty"`
	Groups          string               `json:"groups,omitempty"`
	VerifyMode      *int                 `json:"verify_mode,omitempty"`
	SessionReused   *bool                `json:"session_reused,omitempty"`
	VerifyResult    *int                 `json:"verify_result,omitempty"`
	NegotiatedGroup *int                 `json:"negotiated_group,omitempty"`
	TLSVersion      string               `json:"tls_version,omitempty"`
	CipherSuite     string               `json:"cipher_suite,omitempty"`
	ALPN            string               `json:"alpn,omitempty"`
	Certificates    []CertificateSummary `json:"certificates,omitempty"`
	KeyStatus       KeyStatus            `json:"key_status"`
	KeyStatusNote   string               `json:"key_status_note,omitempty"`
	KeyLogLines     []string             `json:"key_log_lines,omitempty"`
	CaptureMode     CaptureMode          `json:"capture_mode"`
	FirstSeen       time.Time            `json:"first_seen,omitempty"`
	LastSeen        time.Time            `json:"last_seen,omitempty"`
}

type PlaintextStreams struct {
	ClientToServer []byte
	ServerToClient []byte
}

type SessionSnapshot struct {
	Metadata    SessionMetadata  `json:"metadata"`
	Streams     PlaintextStreams `json:"-"`
	FinalizedAt time.Time        `json:"finalized_at,omitempty"`
}

type SessionMetadataUpdate struct {
	Key             SessionKey
	ObservedAt      time.Time
	PID             int
	ExePath         string
	LibraryPath     string
	Source          *Endpoint
	Destination     *Endpoint
	Role            string
	SocketFD        *int
	SNI             string
	Priority        string
	Groups          string
	VerifyMode      *int
	SessionReused   *bool
	VerifyResult    *int
	NegotiatedGroup *int
	TLSVersion      string
	CipherSuite     string
	ALPN            string
	Certificates    []CertificateSummary
	KeyStatus       KeyStatus
	KeyStatusNote   string
	KeyLogLines     []string
	CaptureMode     CaptureMode
}

type PlaintextChunk struct {
	Key        SessionKey
	Direction  StreamDirection
	ObservedAt time.Time
	Data       []byte
}
