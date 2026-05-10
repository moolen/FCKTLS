package fcktls

import (
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	goTLSClientHandshakeSymbol = "crypto/tls.(*Conn).clientHandshake"
	goTLSServerHandshakeSymbol = "crypto/tls.(*Conn).serverHandshake"
	goTLSConnectionStateSymbol = "crypto/tls.(*Conn).ConnectionState"
)

type goBinaryInspection struct {
	IsGoBinary bool
	BinaryPath string
	GoVersion  string
	Symbols    map[string]struct{}
}

func (i goBinaryInspection) SupportsCryptoTLS() bool {
	if !i.IsGoBinary {
		return false
	}
	if _, ok := i.Symbols[goTLSConnectionStateSymbol]; !ok {
		return false
	}
	_, hasClient := i.Symbols[goTLSClientHandshakeSymbol]
	_, hasServer := i.Symbols[goTLSServerHandshakeSymbol]
	return hasClient || hasServer
}

func InspectGoBinary(path string) (goBinaryInspection, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return goBinaryInspection{}, nil
	}

	symbols, err := readELFSymbolSet(path)
	if err != nil {
		return goBinaryInspection{}, fmt.Errorf("read ELF symbols for %q: %w", path, err)
	}

	resolvedPath := path
	if linkTarget, err := os.Readlink(path); err == nil {
		if filepath.IsAbs(linkTarget) {
			resolvedPath = linkTarget
		} else {
			resolvedPath = filepath.Join(filepath.Dir(path), linkTarget)
		}
	}

	return goBinaryInspection{
		IsGoBinary: true,
		BinaryPath: resolvedPath,
		GoVersion:  strings.TrimSpace(info.GoVersion),
		Symbols:    symbols,
	}, nil
}

func readELFSymbolSet(path string) (map[string]struct{}, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	symbols := make(map[string]struct{})
	load := func(entries []elf.Symbol, err error) error {
		if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			return err
		}

		for _, entry := range entries {
			name := strings.TrimSpace(entry.Name)
			if name == "" {
				continue
			}
			symbols[name] = struct{}{}
		}

		return nil
	}

	if err := load(file.Symbols()); err != nil {
		return nil, err
	}
	if err := load(file.DynamicSymbols()); err != nil {
		return nil, err
	}

	return symbols, nil
}
