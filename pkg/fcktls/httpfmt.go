package fcktls

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"
)

type HTTPKind string

const (
	HTTPKindRequest  HTTPKind = "http_request"
	HTTPKindResponse HTTPKind = "http_response"
	HTTPKindText     HTTPKind = "text"
	HTTPKindBinary   HTTPKind = "binary"
)

type HTTPFormat struct {
	Kind   HTTPKind
	Parsed bool
	Text   string
}

func FormatHTTP(direction StreamDirection, data []byte) HTTPFormat {
	if len(data) == 0 {
		return HTTPFormat{Kind: HTTPKindText}
	}

	switch direction {
	case StreamDirectionClientToServer:
		if formatted, ok := formatHTTPRequest(data); ok {
			return formatted
		}
	case StreamDirectionServerToClient:
		if formatted, ok := formatHTTPResponse(data); ok {
			return formatted
		}
	}

	if isTextPayload(data) {
		return HTTPFormat{
			Kind: HTTPKindText,
			Text: string(data),
		}
	}

	return HTTPFormat{
		Kind: HTTPKindBinary,
		Text: hex.Dump(data),
	}
}

func formatHTTPRequest(data []byte) (HTTPFormat, bool) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return HTTPFormat{}, false
	}
	defer req.Body.Close()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return HTTPFormat{}, false
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, "%s %s %s\n", req.Method, req.URL.RequestURI(), req.Proto)
	if req.Host != "" {
		fmt.Fprintf(&builder, "Host: %s\n", req.Host)
	}
	writeSortedHeaders(&builder, req.Header)
	if len(body) > 0 {
		builder.WriteString("\n")
		builder.Write(body)
	}

	return HTTPFormat{
		Kind:   HTTPKindRequest,
		Parsed: true,
		Text:   builder.String(),
	}, true
}

func formatHTTPResponse(data []byte) (HTTPFormat, bool) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), &http.Request{Method: http.MethodGet})
	if err != nil {
		return HTTPFormat{}, false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return HTTPFormat{}, false
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, "%s %s\n", resp.Proto, resp.Status)
	writeSortedHeaders(&builder, resp.Header)
	if len(body) > 0 {
		builder.WriteString("\n")
		builder.Write(body)
	}

	return HTTPFormat{
		Kind:   HTTPKindResponse,
		Parsed: true,
		Text:   builder.String(),
	}, true
}

func writeSortedHeaders(builder *strings.Builder, header http.Header) {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		for _, value := range header.Values(key) {
			fmt.Fprintf(builder, "%s: %s\n", key, value)
		}
	}
}

func isTextPayload(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}

	printable := 0
	for _, b := range data {
		switch {
		case b == '\n' || b == '\r' || b == '\t':
			printable++
		case b >= 32 && b <= 126:
			printable++
		}
	}

	return printable*100 >= len(data)*85
}
