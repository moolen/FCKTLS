//go:build linux && amd64

package fcktls

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	libSSLPattern    = regexp.MustCompile(`^libssl\.so(?:\.[0-9]+)*$`)
	libCryptoPattern = regexp.MustCompile(`^libcrypto\.so(?:\.[0-9]+)*$`)

	openSSLSymbolCache sync.Map
)

const (
	remoteStackReserve     = 16 * 1024
	remoteStringLimit      = 4096
	remoteCertificateLimit = 1024
)

type openSSLRemoteInspector struct{}

type procMapEntry struct {
	start  uintptr
	offset uintptr
	path   string
}

type remoteSymbolResolver struct {
	loadBases map[string]uintptr
	libssl    string
	libcrypto string
}

type remoteProcess struct {
	pid       int
	savedRegs unix.PtraceRegs
	trapAddr  uintptr
	trapCode  []byte
	attached  bool
}

func newDefaultOpenSSLInspector() OpenSSLInspector {
	return &openSSLRemoteInspector{}
}

func (i *openSSLRemoteInspector) Inspect(pid int, sslPtr uint64) (OpenSSLInspection, error) {
	if pid <= 0 || sslPtr == 0 {
		return OpenSSLInspection{}, nil
	}

	resolver, err := newRemoteSymbolResolver(pid)
	if err != nil {
		return OpenSSLInspection{}, err
	}

	proc, err := attachRemoteProcess(pid)
	if err != nil {
		return OpenSSLInspection{}, err
	}
	defer proc.Close()

	inspection := OpenSSLInspection{
		KeyStatus:     KeyStatusUnavailable,
		KeyStatusNote: "key export unavailable",
	}

	if inspection.TLSVersion, err = readOpenSSLVersion(proc, resolver, uintptr(sslPtr)); err != nil {
		return OpenSSLInspection{}, err
	}
	if inspection.CipherSuite, err = readOpenSSLCipher(proc, resolver, uintptr(sslPtr)); err != nil {
		return OpenSSLInspection{}, err
	}
	if inspection.ALPN, err = readOpenSSLALPN(proc, resolver, uintptr(sslPtr)); err != nil {
		return OpenSSLInspection{}, err
	}
	if cert, err := readOpenSSLPeerCertificate(proc, resolver, uintptr(sslPtr)); err != nil {
		return OpenSSLInspection{}, err
	} else if cert.Subject != "" || cert.Issuer != "" {
		inspection.Certificates = []CertificateSummary{cert}
	}

	keyLogLines, err := readOpenSSLKeyLogLines(proc, resolver, uintptr(sslPtr), inspection.TLSVersion)
	if err != nil {
		return OpenSSLInspection{}, err
	}
	if len(keyLogLines) > 0 {
		inspection.KeyLogLines = keyLogLines
		inspection.KeyStatus = KeyStatusAvailable
		inspection.KeyStatusNote = "openssl key log exported"
	}

	return inspection, nil
}

func newRemoteSymbolResolver(pid int) (*remoteSymbolResolver, error) {
	entries, err := parseProcMaps(filepath.Join("/proc", fmt.Sprintf("%d", pid), "maps"))
	if err != nil {
		return nil, fmt.Errorf("parse proc maps: %w", err)
	}

	resolver := &remoteSymbolResolver{loadBases: make(map[string]uintptr)}
	for _, entry := range entries {
		base, ok := resolver.loadBases[entry.path]
		candidate := entry.start - entry.offset
		if !ok || candidate < base {
			resolver.loadBases[entry.path] = candidate
		}
		baseName := filepath.Base(entry.path)
		switch {
		case resolver.libssl == "" && libSSLPattern.MatchString(baseName):
			resolver.libssl = entry.path
		case resolver.libcrypto == "" && libCryptoPattern.MatchString(baseName):
			resolver.libcrypto = entry.path
		}
	}

	if resolver.libssl == "" {
		return nil, errors.New("libssl mapping not found")
	}
	if resolver.libcrypto == "" {
		return nil, errors.New("libcrypto mapping not found")
	}
	return resolver, nil
}

func (r *remoteSymbolResolver) mustResolve(libPath string, symbol string) (uintptr, error) {
	base, ok := r.loadBases[libPath]
	if !ok {
		return 0, fmt.Errorf("load base not found for %s", libPath)
	}
	offsets, err := loadDynamicSymbolOffsets(libPath)
	if err != nil {
		return 0, err
	}
	value, ok := offsets[symbol]
	if !ok || value == 0 {
		return 0, fmt.Errorf("symbol %s not found in %s", symbol, libPath)
	}
	return base + uintptr(value), nil
}

func loadDynamicSymbolOffsets(path string) (map[string]uint64, error) {
	if cached, ok := openSSLSymbolCache.Load(path); ok {
		return cached.(map[string]uint64), nil
	}

	file, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open elf %s: %w", path, err)
	}
	defer file.Close()

	symbols, err := file.DynamicSymbols()
	if err != nil {
		return nil, fmt.Errorf("read dynamic symbols %s: %w", path, err)
	}

	offsets := make(map[string]uint64, len(symbols))
	for _, symbol := range symbols {
		name := symbol.Name
		if idx := strings.IndexByte(name, '@'); idx >= 0 {
			name = name[:idx]
		}
		if name == "" || symbol.Value == 0 {
			continue
		}
		offsets[name] = symbol.Value
	}
	openSSLSymbolCache.Store(path, offsets)
	return offsets, nil
}

func parseProcMaps(path string) ([]procMapEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var out []procMapEntry
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 6 {
			continue
		}
		path := normalizeMappedLibraryPath(strings.Join(fields[5:], " "))
		if !filepath.IsAbs(path) {
			continue
		}
		var start, end, offset uint64
		if _, err := fmt.Sscanf(fields[0], "%x-%x", &start, &end); err != nil {
			continue
		}
		if _, err := fmt.Sscanf(fields[2], "%x", &offset); err != nil {
			continue
		}
		out = append(out, procMapEntry{
			start:  uintptr(start),
			offset: uintptr(offset),
			path:   path,
		})
	}
	return out, nil
}

func attachRemoteProcess(pid int) (*remoteProcess, error) {
	if err := unix.PtraceAttach(pid); err != nil {
		return nil, fmt.Errorf("ptrace attach: %w", err)
	}
	if err := waitForStop(pid); err != nil {
		_ = unix.PtraceDetach(pid)
		return nil, err
	}

	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		_ = unix.PtraceDetach(pid)
		return nil, fmt.Errorf("ptrace get regs: %w", err)
	}

	trapCode := make([]byte, 8)
	if _, err := unix.PtracePeekData(pid, uintptr(regs.Rip), trapCode); err != nil {
		_ = unix.PtraceDetach(pid)
		return nil, fmt.Errorf("ptrace peek trap code: %w", err)
	}

	return &remoteProcess{
		pid:       pid,
		savedRegs: regs,
		trapAddr:  uintptr(regs.Rip),
		trapCode:  trapCode,
		attached:  true,
	}, nil
}

func (p *remoteProcess) Close() error {
	if p == nil || !p.attached {
		return nil
	}
	_ = unix.PtraceSetRegs(p.pid, &p.savedRegs)
	_, _ = unix.PtracePokeData(p.pid, p.trapAddr, p.trapCode)
	p.attached = false
	return unix.PtraceDetach(p.pid)
}

func (p *remoteProcess) Call(function uintptr, scratchSize int, args ...uintptr) (uint64, uintptr, error) {
	if p == nil || !p.attached {
		return 0, 0, errors.New("remote process is not attached")
	}

	patch := append([]byte(nil), p.trapCode...)
	patch[0] = 0xcc
	if _, err := unix.PtracePokeData(p.pid, p.trapAddr, patch); err != nil {
		return 0, 0, fmt.Errorf("ptrace patch trap: %w", err)
	}
	defer func() {
		_, _ = unix.PtracePokeData(p.pid, p.trapAddr, p.trapCode)
		_ = unix.PtraceSetRegs(p.pid, &p.savedRegs)
	}()

	scratchBase, returnAddrSlot := p.scratchLayout(scratchSize)
	if err := p.writeUint64(returnAddrSlot, uint64(p.trapAddr)); err != nil {
		return 0, 0, err
	}

	regs := p.savedRegs
	regs.Rip = uint64(function)
	regs.Rsp = uint64(returnAddrSlot)
	if len(args) > 0 {
		regs.Rdi = uint64(args[0])
	}
	if len(args) > 1 {
		regs.Rsi = uint64(args[1])
	}
	if len(args) > 2 {
		regs.Rdx = uint64(args[2])
	}
	if len(args) > 3 {
		regs.Rcx = uint64(args[3])
	}
	if len(args) > 4 {
		regs.R8 = uint64(args[4])
	}
	if len(args) > 5 {
		regs.R9 = uint64(args[5])
	}
	if err := unix.PtraceSetRegs(p.pid, &regs); err != nil {
		return 0, 0, fmt.Errorf("ptrace set regs: %w", err)
	}
	if err := unix.PtraceCont(p.pid, 0); err != nil {
		return 0, 0, fmt.Errorf("ptrace cont: %w", err)
	}
	if err := waitForTrap(p.pid); err != nil {
		return 0, 0, err
	}

	var out unix.PtraceRegs
	if err := unix.PtraceGetRegs(p.pid, &out); err != nil {
		return 0, 0, fmt.Errorf("ptrace get result regs: %w", err)
	}
	return out.Rax, scratchBase, nil
}

func (p *remoteProcess) scratchLayout(scratchSize int) (uintptr, uintptr) {
	scratchSize = alignUp(maxInt(scratchSize, remoteStackReserve), 16)
	stackTop := alignDown(uintptr(p.savedRegs.Rsp)-0x200, 16)
	returnAddrSlot := stackTop - 8
	scratchBase := alignDown(returnAddrSlot-uintptr(scratchSize), 16)
	return scratchBase, returnAddrSlot
}

func waitForStop(pid int) error {
	for {
		var status unix.WaitStatus
		_, err := unix.Wait4(pid, &status, 0, nil)
		if err != nil {
			return fmt.Errorf("wait4 stop: %w", err)
		}
		if status.Stopped() {
			return nil
		}
		if status.Exited() || status.Signaled() {
			return fmt.Errorf("process exited while stopping")
		}
	}
}

func waitForTrap(pid int) error {
	for {
		var status unix.WaitStatus
		_, err := unix.Wait4(pid, &status, 0, nil)
		if err != nil {
			return fmt.Errorf("wait4 trap: %w", err)
		}
		if status.Stopped() {
			if status.StopSignal() == unix.SIGTRAP {
				return nil
			}
			return fmt.Errorf("unexpected stop signal %s", status.StopSignal())
		}
		if status.Exited() || status.Signaled() {
			return fmt.Errorf("process exited during remote call")
		}
	}
}

func (p *remoteProcess) readMemory(addr uintptr, size int) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	iov := unix.Iovec{Base: &buf[0]}
	iov.SetLen(size)
	remote := unix.RemoteIovec{Base: addr, Len: size}
	n, err := unix.ProcessVMReadv(p.pid, []unix.Iovec{iov}, []unix.RemoteIovec{remote}, 0)
	if err != nil {
		return nil, fmt.Errorf("process_vm_readv %#x: %w", addr, err)
	}
	if n != size {
		return nil, fmt.Errorf("short process_vm_readv: got %d want %d", n, size)
	}
	return buf, nil
}

func (p *remoteProcess) writeMemory(addr uintptr, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	iov := unix.Iovec{Base: &data[0]}
	iov.SetLen(len(data))
	remote := unix.RemoteIovec{Base: addr, Len: len(data)}
	n, err := unix.ProcessVMWritev(p.pid, []unix.Iovec{iov}, []unix.RemoteIovec{remote}, 0)
	if err != nil {
		return fmt.Errorf("process_vm_writev %#x: %w", addr, err)
	}
	if n != len(data) {
		return fmt.Errorf("short process_vm_writev: got %d want %d", n, len(data))
	}
	return nil
}

func (p *remoteProcess) writeUint64(addr uintptr, value uint64) error {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], value)
	return p.writeMemory(addr, buf[:])
}

func (p *remoteProcess) readCString(addr uintptr, max int) (string, error) {
	if addr == 0 || max <= 0 {
		return "", nil
	}
	data, err := p.readMemory(addr, max)
	if err != nil {
		return "", err
	}
	if idx := bytes.IndexByte(data, 0); idx >= 0 {
		data = data[:idx]
	}
	return strings.TrimSpace(string(data)), nil
}

func readOpenSSLVersion(proc *remoteProcess, resolver *remoteSymbolResolver, ssl uintptr) (string, error) {
	addr, err := resolver.mustResolve(resolver.libssl, "SSL_get_version")
	if err != nil {
		return "", err
	}
	ptr, _, err := proc.Call(addr, 0, ssl)
	if err != nil {
		return "", err
	}
	return proc.readCString(uintptr(ptr), remoteStringLimit)
}

func readOpenSSLCipher(proc *remoteProcess, resolver *remoteSymbolResolver, ssl uintptr) (string, error) {
	getCurrentCipher, err := resolver.mustResolve(resolver.libssl, "SSL_get_current_cipher")
	if err != nil {
		return "", err
	}
	cipherPtr, _, err := proc.Call(getCurrentCipher, 0, ssl)
	if err != nil {
		return "", err
	}
	if cipherPtr == 0 {
		return "", nil
	}

	getCipherName, err := resolver.mustResolve(resolver.libssl, "SSL_CIPHER_get_name")
	if err != nil {
		return "", err
	}
	namePtr, _, err := proc.Call(getCipherName, 0, uintptr(cipherPtr))
	if err != nil {
		return "", err
	}
	return proc.readCString(uintptr(namePtr), remoteStringLimit)
}

func readOpenSSLALPN(proc *remoteProcess, resolver *remoteSymbolResolver, ssl uintptr) (string, error) {
	addr, err := resolver.mustResolve(resolver.libssl, "SSL_get0_alpn_selected")
	if err != nil {
		return "", err
	}
	scratch, _ := proc.scratchLayout(64)
	_, scratch, err = proc.Call(addr, 64, ssl, scratch, scratch+8)
	if err != nil {
		return "", err
	}
	data, err := proc.readMemory(scratch, 16)
	if err != nil {
		return "", err
	}
	ptr := binary.LittleEndian.Uint64(data[:8])
	length := binary.LittleEndian.Uint32(data[8:12])
	if ptr == 0 || length == 0 {
		return "", nil
	}
	raw, err := proc.readMemory(uintptr(ptr), int(length))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func readOpenSSLPeerCertificate(proc *remoteProcess, resolver *remoteSymbolResolver, ssl uintptr) (CertificateSummary, error) {
	getPeer, err := resolver.mustResolve(resolver.libssl, "SSL_get1_peer_certificate")
	if err != nil {
		return CertificateSummary{}, err
	}
	x509Ptr, _, err := proc.Call(getPeer, 0, ssl)
	if err != nil {
		return CertificateSummary{}, err
	}
	if x509Ptr == 0 {
		return CertificateSummary{}, nil
	}
	defer func() {
		if freeAddr, err := resolver.mustResolve(resolver.libcrypto, "X509_free"); err == nil {
			_, _, _ = proc.Call(freeAddr, 0, uintptr(x509Ptr))
		}
	}()

	subjectGetter, err := resolver.mustResolve(resolver.libcrypto, "X509_get_subject_name")
	if err != nil {
		return CertificateSummary{}, err
	}
	issuerGetter, err := resolver.mustResolve(resolver.libcrypto, "X509_get_issuer_name")
	if err != nil {
		return CertificateSummary{}, err
	}
	oneline, err := resolver.mustResolve(resolver.libcrypto, "X509_NAME_oneline")
	if err != nil {
		return CertificateSummary{}, err
	}

	subjectNamePtr, _, err := proc.Call(subjectGetter, 0, uintptr(x509Ptr))
	if err != nil {
		return CertificateSummary{}, err
	}
	issuerNamePtr, _, err := proc.Call(issuerGetter, 0, uintptr(x509Ptr))
	if err != nil {
		return CertificateSummary{}, err
	}

	subject, err := readX509Name(proc, oneline, uintptr(subjectNamePtr))
	if err != nil {
		return CertificateSummary{}, err
	}
	issuer, err := readX509Name(proc, oneline, uintptr(issuerNamePtr))
	if err != nil {
		return CertificateSummary{}, err
	}
	return CertificateSummary{Subject: subject, Issuer: issuer}, nil
}

func readX509Name(proc *remoteProcess, oneline uintptr, namePtr uintptr) (string, error) {
	if namePtr == 0 {
		return "", nil
	}
	scratch, _ := proc.scratchLayout(remoteCertificateLimit)
	_, scratch, err := proc.Call(oneline, remoteCertificateLimit, namePtr, scratch, uintptr(remoteCertificateLimit))
	if err != nil {
		return "", err
	}
	return proc.readCString(scratch, remoteCertificateLimit)
}

func readOpenSSLKeyLogLines(proc *remoteProcess, resolver *remoteSymbolResolver, ssl uintptr, tlsVersion string) ([]string, error) {
	getSession, err := resolver.mustResolve(resolver.libssl, "SSL_get1_session")
	if err != nil {
		return nil, err
	}
	sessionPtr, _, err := proc.Call(getSession, 0, ssl)
	if err != nil {
		return nil, err
	}
	if sessionPtr == 0 {
		return nil, nil
	}
	defer func() {
		if freeAddr, err := resolver.mustResolve(resolver.libssl, "SSL_SESSION_free"); err == nil {
			_, _, _ = proc.Call(freeAddr, 0, uintptr(sessionPtr))
		}
	}()

	lines, err := readSessionPrintKeyLog(proc, resolver, uintptr(sessionPtr))
	if err != nil {
		return nil, err
	}
	if len(lines) > 0 {
		return lines, nil
	}

	if strings.Contains(tlsVersion, "1.3") {
		return nil, nil
	}

	return readClientRandomMasterKey(proc, resolver, ssl, uintptr(sessionPtr))
}

func readSessionPrintKeyLog(proc *remoteProcess, resolver *remoteSymbolResolver, session uintptr) ([]string, error) {
	bioSMem, err := resolver.mustResolve(resolver.libcrypto, "BIO_s_mem")
	if err != nil {
		return nil, nil
	}
	bioNew, err := resolver.mustResolve(resolver.libcrypto, "BIO_new")
	if err != nil {
		return nil, nil
	}
	bioCtrlPending, err := resolver.mustResolve(resolver.libcrypto, "BIO_ctrl_pending")
	if err != nil {
		return nil, nil
	}
	bioRead, err := resolver.mustResolve(resolver.libcrypto, "BIO_read")
	if err != nil {
		return nil, nil
	}
	bioFree, err := resolver.mustResolve(resolver.libcrypto, "BIO_free")
	if err != nil {
		return nil, nil
	}
	printKeyLog, err := resolver.mustResolve(resolver.libssl, "SSL_SESSION_print_keylog")
	if err != nil {
		return nil, nil
	}

	methodPtr, _, err := proc.Call(bioSMem, 0)
	if err != nil || methodPtr == 0 {
		return nil, err
	}
	bioPtr, _, err := proc.Call(bioNew, 0, uintptr(methodPtr))
	if err != nil || bioPtr == 0 {
		return nil, err
	}
	defer func() {
		_, _, _ = proc.Call(bioFree, 0, uintptr(bioPtr))
	}()

	rc, _, err := proc.Call(printKeyLog, 0, uintptr(bioPtr), session)
	if err != nil || rc == 0 {
		return nil, err
	}

	pending, _, err := proc.Call(bioCtrlPending, 0, uintptr(bioPtr))
	if err != nil || pending == 0 || pending > 16*1024 {
		return nil, err
	}
	scratch, _ := proc.scratchLayout(int(pending) + 64)
	readN, scratch, err := proc.Call(bioRead, int(pending)+64, uintptr(bioPtr), scratch, uintptr(pending))
	if err != nil || readN == 0 {
		return nil, err
	}
	buf, err := proc.readMemory(scratch, int(readN))
	if err != nil {
		return nil, err
	}
	return parseKeyLogLines(string(buf)), nil
}

func readClientRandomMasterKey(proc *remoteProcess, resolver *remoteSymbolResolver, ssl uintptr, session uintptr) ([]string, error) {
	getClientRandom, err := resolver.mustResolve(resolver.libssl, "SSL_get_client_random")
	if err != nil {
		return nil, err
	}
	getMasterKey, err := resolver.mustResolve(resolver.libssl, "SSL_SESSION_get_master_key")
	if err != nil {
		return nil, err
	}

	scratch, _ := proc.scratchLayout(128)
	clientRandomLen, scratch, err := proc.Call(getClientRandom, 128, ssl, scratch, 64)
	if err != nil || clientRandomLen == 0 || clientRandomLen > 64 {
		return nil, err
	}
	clientRandom, err := proc.readMemory(scratch, int(clientRandomLen))
	if err != nil {
		return nil, err
	}

	keyScratch, _ := proc.scratchLayout(512)
	masterKeyLen, keyScratch, err := proc.Call(getMasterKey, 512, session, keyScratch, 256)
	if err != nil || masterKeyLen == 0 || masterKeyLen > 256 {
		return nil, err
	}
	masterKey, err := proc.readMemory(keyScratch, int(masterKeyLen))
	if err != nil {
		return nil, err
	}

	line := fmt.Sprintf("CLIENT_RANDOM %s %s", strings.ToUpper(hex.EncodeToString(clientRandom)), strings.ToUpper(hex.EncodeToString(masterKey)))
	return []string{line}, nil
}

func parseKeyLogLines(raw string) []string {
	parts := strings.Split(raw, "\n")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func normalizeMappedLibraryPath(path string) string {
	return strings.TrimSpace(strings.TrimSuffix(path, " (deleted)"))
}

func alignDown(value uintptr, align int) uintptr {
	mask := uintptr(align - 1)
	return value &^ mask
}

func alignUp(value int, align int) int {
	return (value + align - 1) &^ (align - 1)
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}
	return right
}
