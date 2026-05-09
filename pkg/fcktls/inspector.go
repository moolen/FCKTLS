package fcktls

type OpenSSLInspector interface {
	Inspect(pid int, sslPtr uint64) (OpenSSLInspection, error)
}

type OpenSSLInspection struct {
	TLSVersion    string
	CipherSuite   string
	ALPN          string
	Certificates  []CertificateSummary
	KeyLogLines   []string
	KeyStatus     KeyStatus
	KeyStatusNote string
}
