package fcktls

import (
	"net"

	"golang.org/x/sys/unix"
)

func resolveSocketTuple(pid int, fd int) (Endpoint, Endpoint, bool, error) {
	if pid <= 0 || fd < 0 {
		return Endpoint{}, Endpoint{}, false, nil
	}

	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return Endpoint{}, Endpoint{}, false, err
	}
	defer unix.Close(pidfd)

	localFD, err := unix.PidfdGetfd(pidfd, fd, 0)
	if err != nil {
		return Endpoint{}, Endpoint{}, false, err
	}
	defer unix.Close(localFD)

	localAddr, err := unix.Getsockname(localFD)
	if err != nil {
		return Endpoint{}, Endpoint{}, false, err
	}
	peerAddr, err := unix.Getpeername(localFD)
	if err != nil {
		return Endpoint{}, Endpoint{}, false, err
	}

	local, ok := sockaddrEndpoint(localAddr)
	if !ok {
		return Endpoint{}, Endpoint{}, false, nil
	}
	peer, ok := sockaddrEndpoint(peerAddr)
	if !ok {
		return Endpoint{}, Endpoint{}, false, nil
	}
	return local, peer, true, nil
}

func sockaddrEndpoint(addr unix.Sockaddr) (Endpoint, bool) {
	switch sa := addr.(type) {
	case *unix.SockaddrInet4:
		return Endpoint{Address: net.IP(sa.Addr[:]).String(), Port: uint16(sa.Port)}, true
	case *unix.SockaddrInet6:
		return Endpoint{Address: net.IP(sa.Addr[:]).String(), Port: uint16(sa.Port)}, true
	default:
		return Endpoint{}, false
	}
}
