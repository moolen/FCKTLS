package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	cebpf "github.com/cilium/ebpf"
)

var collectionSpecFromFile = cebpf.LoadCollectionSpec

type ObjectsUnavailableError struct {
	AttemptedPaths []string
	Cause          error
}

func (e *ObjectsUnavailableError) Error() string {
	msg := "compiled eBPF objects are unavailable; run `go generate ./pkg/ebpf` in an environment with `clang` and `llvm-strip`"
	if len(e.AttemptedPaths) > 0 {
		msg = fmt.Sprintf("%s (searched: %s)", msg, strings.Join(e.AttemptedPaths, ", "))
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e *ObjectsUnavailableError) Unwrap() error {
	return e.Cause
}

func candidateNamedObjectPaths(objectName string) []string {
	candidates := []string{
		objectName,
		filepath.Join("pkg", "ebpf", objectName),
	}

	_, callerFile, _, ok := runtime.Caller(0)
	if ok {
		candidates = append(candidates, filepath.Join(filepath.Dir(callerFile), objectName))
	}

	unique := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		if _, err := os.Stat(candidate); err == nil {
			unique = append(unique, candidate)
		}
	}

	return unique
}

func loadNamedCollectionSpec(objectName string) (*cebpf.CollectionSpec, error) {
	candidates := candidateNamedObjectPaths(objectName)
	if len(candidates) == 0 {
		return nil, &ObjectsUnavailableError{}
	}

	loadErrs := make([]error, 0, len(candidates))
	for _, path := range candidates {
		spec, err := collectionSpecFromFile(path)
		if err == nil {
			return spec, nil
		}
		loadErrs = append(loadErrs, fmt.Errorf("%s: %w", path, err))
	}

	return nil, &ObjectsUnavailableError{
		AttemptedPaths: append([]string(nil), candidates...),
		Cause:          errors.Join(loadErrs...),
	}
}
