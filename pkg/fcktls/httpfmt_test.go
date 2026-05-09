package fcktls

import (
	"strings"
	"testing"
)

func TestFormatHTTPParsesRequest(t *testing.T) {
	formatted := FormatHTTP(StreamDirectionClientToServer, []byte("GET /hello HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nworld"))

	if !formatted.Parsed {
		t.Fatal("Parsed = false, want true")
	}

	if formatted.Kind != HTTPKindRequest {
		t.Fatalf("Kind = %q, want %q", formatted.Kind, HTTPKindRequest)
	}

	if !strings.Contains(formatted.Text, "GET /hello HTTP/1.1") {
		t.Fatalf("Text = %q, want request line", formatted.Text)
	}

	if !strings.Contains(formatted.Text, "world") {
		t.Fatalf("Text = %q, want body", formatted.Text)
	}
}

func TestFormatHTTPFallsBackToText(t *testing.T) {
	formatted := FormatHTTP(StreamDirectionClientToServer, []byte("not http but still text"))

	if formatted.Parsed {
		t.Fatal("Parsed = true, want false")
	}

	if formatted.Kind != HTTPKindText {
		t.Fatalf("Kind = %q, want %q", formatted.Kind, HTTPKindText)
	}
}

func TestFormatHTTPFallsBackToBinary(t *testing.T) {
	formatted := FormatHTTP(StreamDirectionServerToClient, []byte{0x00, 0x01, 0x02, 0x03})

	if formatted.Parsed {
		t.Fatal("Parsed = true, want false")
	}

	if formatted.Kind != HTTPKindBinary {
		t.Fatalf("Kind = %q, want %q", formatted.Kind, HTTPKindBinary)
	}

	if !strings.Contains(formatted.Text, "00000000") {
		t.Fatalf("Text = %q, want hex dump", formatted.Text)
	}
}
