//go:build !linux || !amd64

package fcktls

func newDefaultOpenSSLInspector() OpenSSLInspector {
	return nil
}
