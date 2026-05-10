package ebpf

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type uprobeAttachSpec struct {
	symbol   string
	offset   uint64
	enter    *cebpf.Program
	ret      *cebpf.Program
	optional bool
}

func attachUprobeSpecs(executable *link.Executable, libraryPath string, specs []uprobeAttachSpec) ([]link.Link, error) {
	return attachUprobeSpecsWithOps(
		libraryPath,
		specs,
		func(symbol string, prog *cebpf.Program) (link.Link, error) {
			var offset uint64
			for _, spec := range specs {
				if spec.symbol == symbol && spec.enter == prog {
					offset = spec.offset
					break
				}
			}
			return executable.Uprobe(symbol, prog, &link.UprobeOptions{Offset: offset})
		},
		func(symbol string, prog *cebpf.Program) (link.Link, error) {
			var offset uint64
			for _, spec := range specs {
				if spec.symbol == symbol && spec.ret == prog {
					offset = spec.offset
					break
				}
			}
			return executable.Uretprobe(symbol, prog, &link.UprobeOptions{Offset: offset})
		},
	)
}

func attachUprobeSpecsWithOps[T io.Closer](
	libraryPath string,
	specs []uprobeAttachSpec,
	attach func(symbol string, prog *cebpf.Program) (T, error),
	attachRet func(symbol string, prog *cebpf.Program) (T, error),
) ([]T, error) {
	var links []T
	for _, spec := range specs {
		up, err := attach(spec.symbol, spec.enter)
		if err != nil {
			if spec.optional && isMissingUprobeSymbolError(spec.symbol, err) {
				continue
			}
			closeClosers(links)
			return nil, fmt.Errorf("attach uprobe %s to %s: %w", spec.symbol, filepath.Base(libraryPath), err)
		}
		links = append(links, up)
		if spec.ret == nil {
			continue
		}

		ret, err := attachRet(spec.symbol, spec.ret)
		if err != nil {
			if spec.optional && isMissingUprobeSymbolError(spec.symbol, err) {
				_ = up.Close()
				links = links[:len(links)-1]
				continue
			}
			closeClosers(links)
			return nil, fmt.Errorf("attach uretprobe %s to %s: %w", spec.symbol, filepath.Base(libraryPath), err)
		}
		links = append(links, ret)
	}
	return links, nil
}

func closeClosers[T io.Closer](items []T) {
	for _, item := range items {
		_ = item.Close()
	}
}

func closeLinks(items []link.Link) {
	for _, item := range items {
		_ = item.Close()
	}
}

func isMissingUprobeSymbolError(symbol string, err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	sym := strings.ToLower(symbol)
	return strings.Contains(msg, "not found") && strings.Contains(msg, sym)
}
