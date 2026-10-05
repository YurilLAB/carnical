// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"net"
	"syscall"
	"time"
)

const tcpUserTimeout = 0x12 // TCP_USER_TIMEOUT, not in package syscall

type syscallConner interface {
	SyscallConn() (syscall.RawConn, error)
}

// setDeferAccept asks the kernel to complete a connection to the listener only when the client has sent data (or after
// d). It works on any TCP listener, including one systemd passed in.
func setDeferAccept(ln net.Listener, d time.Duration) error {
	sc, ok := ln.(syscallConner)
	if !ok {
		return nil
	}
	return control(sc, func(fd int) error {
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_DEFER_ACCEPT, int(d/time.Second))
	})
}

// DeferAccept reports the listener's TCP_DEFER_ACCEPT in seconds (for tests and the host checks).
func DeferAccept(ln net.Listener) (int, error) {
	if l, ok := ln.(*listener); ok {
		ln = l.Listener
	}
	sc, ok := ln.(syscallConner)
	if !ok {
		return 0, nil
	}
	v := 0
	err := control(sc, func(fd int) (err error) {
		v, err = syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_DEFER_ACCEPT)
		return err
	})
	return v, err
}

// setUserTimeout makes the kernel drop the connection when data it sent stays unacknowledged for d: a client that
// stops reading (or advertises a zero window) cannot hold the connection and its buffers for ever.
func setUserTimeout(c net.Conn, d time.Duration) error {
	sc, ok := c.(syscallConner)
	if !ok {
		return nil
	}
	return control(sc, func(fd int) error {
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, tcpUserTimeout, int(d/time.Millisecond))
	})
}

func control(sc syscallConner, f func(fd int) error) error {
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := raw.Control(func(fd uintptr) { ferr = f(int(fd)) }); err != nil {
		return err
	}
	return ferr
}
