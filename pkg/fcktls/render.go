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
	fmt.Fprintf(
		&builder,
		"sni=%s tls=%s cipher=%s alpn=%s key_status=%s capture=%s",
		metadata.SNI,
		metadata.TLSVersion,
		metadata.CipherSuite,
		metadata.ALPN,
		metadata.KeyStatus.String(),
		metadata.CaptureMode.String(),
	)

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
