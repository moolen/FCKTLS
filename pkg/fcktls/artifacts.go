package fcktls

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type ArtifactWriter struct {
	CacheRoot string
}

type ArtifactPaths struct {
	SessionDir        string
	SummaryJSON       string
	KeysLog           string
	RequestText       string
	ResponseText      string
	ClientToServerBin string
	ServerToClientBin string
}

func NewArtifactWriter(cacheRoot string) ArtifactWriter {
	if strings.TrimSpace(cacheRoot) == "" {
		cacheRoot = defaultCacheRoot()
	}

	return ArtifactWriter{CacheRoot: cacheRoot}
}

func (w ArtifactWriter) WriteSession(snapshot SessionSnapshot) (ArtifactPaths, error) {
	sessionID := snapshot.Metadata.SessionID
	if sessionID == "" {
		sessionID = snapshot.Metadata.Key.String()
	}

	paths := ArtifactPaths{
		SessionDir:        filepath.Join(w.CacheRoot, sessionID),
		SummaryJSON:       filepath.Join(w.CacheRoot, sessionID, "summary.json"),
		ClientToServerBin: filepath.Join(w.CacheRoot, sessionID, "stream-client-to-server.bin"),
		ServerToClientBin: filepath.Join(w.CacheRoot, sessionID, "stream-server-to-client.bin"),
	}

	if err := os.MkdirAll(paths.SessionDir, 0o755); err != nil {
		return ArtifactPaths{}, err
	}

	summary := struct {
		Metadata    SessionMetadata `json:"metadata"`
		FinalizedAt interface{}     `json:"finalized_at,omitempty"`
		StreamSizes struct {
			ClientToServer int `json:"client_to_server"`
			ServerToClient int `json:"server_to_client"`
		} `json:"stream_sizes"`
	}{
		Metadata:    snapshot.Metadata,
		FinalizedAt: snapshot.FinalizedAt,
	}
	summary.StreamSizes.ClientToServer = len(snapshot.Streams.ClientToServer)
	summary.StreamSizes.ServerToClient = len(snapshot.Streams.ServerToClient)

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return ArtifactPaths{}, err
	}

	if err := os.WriteFile(paths.SummaryJSON, append(data, '\n'), 0o644); err != nil {
		return ArtifactPaths{}, err
	}
	if snapshot.Metadata.CaptureMode == CaptureModeCapture {
		if len(snapshot.Streams.ClientToServer) > 0 {
			if err := os.WriteFile(paths.ClientToServerBin, snapshot.Streams.ClientToServer, 0o644); err != nil {
				return ArtifactPaths{}, err
			}
		} else {
			paths.ClientToServerBin = ""
		}
		if len(snapshot.Streams.ServerToClient) > 0 {
			if err := os.WriteFile(paths.ServerToClientBin, snapshot.Streams.ServerToClient, 0o644); err != nil {
				return ArtifactPaths{}, err
			}
		} else {
			paths.ServerToClientBin = ""
		}
	} else {
		paths.ClientToServerBin = ""
		paths.ServerToClientBin = ""
	}

	if len(snapshot.Metadata.KeyLogLines) > 0 {
		paths.KeysLog = filepath.Join(paths.SessionDir, "keys.log")
		if err := os.WriteFile(paths.KeysLog, []byte(strings.Join(snapshot.Metadata.KeyLogLines, "\n")+"\n"), 0o600); err != nil {
			return ArtifactPaths{}, err
		}
	}

	if snapshot.Metadata.CaptureMode == CaptureModeCapture {
		request := FormatHTTP(StreamDirectionClientToServer, snapshot.Streams.ClientToServer)
		if request.Parsed && request.Kind == HTTPKindRequest {
			paths.RequestText = filepath.Join(paths.SessionDir, "request.txt")
			if err := os.WriteFile(paths.RequestText, []byte(request.Text), 0o644); err != nil {
				return ArtifactPaths{}, err
			}
		}

		response := FormatHTTP(StreamDirectionServerToClient, snapshot.Streams.ServerToClient)
		if response.Parsed && response.Kind == HTTPKindResponse {
			paths.ResponseText = filepath.Join(paths.SessionDir, "response.txt")
			if err := os.WriteFile(paths.ResponseText, []byte(response.Text), 0o644); err != nil {
				return ArtifactPaths{}, err
			}
		}
	}

	return paths, nil
}
