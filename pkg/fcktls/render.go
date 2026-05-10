package fcktls

import (
	"fmt"
	"strings"
)

func RenderSessionSummary(snapshot SessionSnapshot) string {
	metadata := snapshot.Metadata
	var builder strings.Builder

	fmt.Fprintf(&builder, "session %s pid=%d exe=%s\n", metadata.SessionID, metadata.PID, metadata.ExePath)
	if src, dst := metadata.Source.String(), metadata.Destination.String(); src != "" || dst != "" {
		fmt.Fprintf(&builder, "peer=%s -> %s\n", src, dst)
	}

	parts := make([]string, 0, 12)
	if metadata.SocketFD != nil {
		parts = append(parts, fmt.Sprintf("fd=%d", *metadata.SocketFD))
	}
	if metadata.SNI != "" {
		parts = append(parts, fmt.Sprintf("sni=%s", metadata.SNI))
	}
	if metadata.Priority != "" {
		parts = append(parts, fmt.Sprintf("priority=%s", metadata.Priority))
	}
	if metadata.Groups != "" {
		parts = append(parts, fmt.Sprintf("groups=%s", metadata.Groups))
	}
	if metadata.VerifyMode != nil {
		parts = append(parts, fmt.Sprintf("verify_mode=%d", *metadata.VerifyMode))
	}
	if metadata.SessionReused != nil {
		parts = append(parts, fmt.Sprintf("session_reused=%t", *metadata.SessionReused))
	}
	if metadata.VerifyResult != nil {
		parts = append(parts, fmt.Sprintf("verify_result=%d", *metadata.VerifyResult))
	}
	if metadata.NegotiatedGroup != nil {
		parts = append(parts, fmt.Sprintf("negotiated_group=%d", *metadata.NegotiatedGroup))
	}
	if metadata.TLSVersion != "" {
		parts = append(parts, fmt.Sprintf("tls=%s", metadata.TLSVersion))
	}
	if metadata.CipherSuite != "" {
		parts = append(parts, fmt.Sprintf("cipher=%s", metadata.CipherSuite))
	}
	if metadata.ALPN != "" {
		parts = append(parts, fmt.Sprintf("alpn=%s", metadata.ALPN))
	}
	if len(metadata.Certificates) > 0 {
		parts = append(parts, fmt.Sprintf("certs=%d", len(metadata.Certificates)))
	}
	parts = append(parts,
		fmt.Sprintf("key_status=%s", metadata.KeyStatus.String()),
		fmt.Sprintf("capture=%s", metadata.CaptureMode.String()),
	)
	builder.WriteString(strings.Join(parts, " "))

	return builder.String()
}

func RenderCapture(snapshot SessionSnapshot) string {
	var builder strings.Builder

	if len(snapshot.Streams.ClientToServer) > 0 {
		formatted := FormatHTTP(StreamDirectionClientToServer, snapshot.Streams.ClientToServer)
		fmt.Fprintf(&builder, "client-to-server\n%s\n", formatted.Text)
	}
	if len(snapshot.Streams.ServerToClient) > 0 {
		formatted := FormatHTTP(StreamDirectionServerToClient, snapshot.Streams.ServerToClient)
		fmt.Fprintf(&builder, "server-to-client\n%s\n", formatted.Text)
	}

	if builder.Len() == 0 {
		return "no plaintext captured"
	}

	return builder.String()
}
