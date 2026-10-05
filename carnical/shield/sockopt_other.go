// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package shield

import (
	"net"
	"time"
)

// The socket options are Linux's; elsewhere the listener is left as it is.

func setDeferAccept(net.Listener, time.Duration) error { return nil }

func setUserTimeout(net.Conn, time.Duration) error { return nil }

// DeferAccept reports 0 outside Linux.
func DeferAccept(net.Listener) (int, error) { return 0, nil }
