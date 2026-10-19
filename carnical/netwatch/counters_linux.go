// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netwatch

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// ReadCounters reads the named counters of the inet table straight from the kernel: one netlink dump of the table's
// counter objects, which touches no set. nft before 1.1.1 (Debian 12, Ubuntu 24.04, RHEL 9) fetches every element of
// every set to list counters, and under a SYN flood from spoofed sources the guards' meters hold some 130,000: a
// listing then took about a second of CPU and 130 MiB, more than the unit allows. It needs CAP_NET_ADMIN, as nft does.
func ReadCounters(ctx context.Context, table string) (map[string]Count, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("netwatch: netlink: %w", err)
	}
	defer unix.Close(fd)
	timeout := 2 * time.Second
	if d, ok := ctx.Deadline(); ok {
		timeout = max(time.Until(d), time.Millisecond)
	}
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, fmt.Errorf("netwatch: netlink: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("netwatch: netlink: %w", err)
	}
	const seq = 1
	if err := unix.Sendto(fd, counterDumpRequest(table, seq), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("netwatch: netlink: %w", err)
	}
	d := counterDump{table: table, seq: seq, out: map[string]Count{}}
	buf := make([]byte, 64<<10)
	for !d.done {
		n, _, flags, _, err := unix.Recvmsg(fd, buf, nil, 0)
		switch {
		case errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK):
			return nil, errors.New("netwatch: the kernel took too long to list the counters")
		case err != nil:
			return nil, fmt.Errorf("netwatch: netlink: %w", err)
		case flags&unix.MSG_TRUNC != 0:
			return nil, errors.New("netwatch: a netlink message was cut short")
		}
		if err := d.add(buf[:n]); err != nil {
			return nil, err
		}
	}
	if len(d.out) == 0 {
		return nil, fmt.Errorf("netwatch: table inet %s has no counters (is the policy loaded?)", table)
	}
	return d.out, nil
}

// counterDumpRequest asks for every counter object of the inet table.
func counterDumpRequest(table string, seq uint32) []byte {
	var attrs []byte
	attrs = appendAttr(attrs, unix.NFTA_OBJ_TABLE, append([]byte(table), 0))
	attrs = appendAttr(attrs, unix.NFTA_OBJ_TYPE, binary.BigEndian.AppendUint32(nil, unix.NFT_OBJECT_COUNTER))
	size := unix.SizeofNlMsghdr + 4 + len(attrs)
	msg := make([]byte, 0, size)
	msg = binary.NativeEndian.AppendUint32(msg, uint32(size)) // #nosec G115 -- a table name of at most 64 bytes
	msg = binary.NativeEndian.AppendUint16(msg, unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETOBJ)
	msg = binary.NativeEndian.AppendUint16(msg, unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	msg = binary.NativeEndian.AppendUint32(msg, seq)
	msg = binary.NativeEndian.AppendUint32(msg, 0)
	msg = append(msg, unix.NFPROTO_INET, unix.NFNETLINK_V0, 0, 0) // nfgenmsg: family, version, resource id
	return append(msg, attrs...)
}

func appendAttr(b []byte, typ uint16, val []byte) []byte {
	b = binary.NativeEndian.AppendUint16(b, uint16(unix.SizeofNlAttr+len(val))) // #nosec G115 -- short values only
	b = binary.NativeEndian.AppendUint16(b, typ)
	b = append(b, val...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// counterDump gathers the replies to one counter dump.
type counterDump struct {
	table string
	seq   uint32
	out   map[string]Count
	done  bool
}

// add reads the netlink messages of one datagram.
func (d *counterDump) add(b []byte) error {
	for len(b) >= unix.SizeofNlMsghdr && !d.done {
		size := int(binary.NativeEndian.Uint32(b))
		typ, flags := binary.NativeEndian.Uint16(b[4:]), binary.NativeEndian.Uint16(b[6:])
		seq := binary.NativeEndian.Uint32(b[8:])
		if size < unix.SizeofNlMsghdr || size > len(b) {
			return errors.New("netwatch: a netlink message is malformed")
		}
		body := b[unix.SizeofNlMsghdr:size]
		b = b[min(nlAlign(size), len(b)):]
		if seq != d.seq {
			continue
		}
		if flags&unix.NLM_F_DUMP_INTR != 0 {
			return errors.New("netwatch: the ruleset changed while the counters were read")
		}
		switch typ {
		case unix.NLMSG_DONE, unix.NLMSG_ERROR:
			if len(body) < 4 {
				return errors.New("netwatch: a netlink message is malformed")
			}
			if errno := int32(binary.NativeEndian.Uint32(body)); errno < 0 { // #nosec G115 -- the kernel's signed error
				return fmt.Errorf("netwatch: listing the counters: %w", unix.Errno(-errno))
			}
			d.done = d.done || typ == unix.NLMSG_DONE
		case unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWOBJ:
			if err := d.object(body); err != nil {
				return err
			}
		}
	}
	return nil
}

// object reads one counter object: its table, name and what it counted.
func (d *counterDump) object(body []byte) error {
	if len(body) < 4 {
		return errors.New("netwatch: a netlink message is malformed")
	}
	var table, name string
	var typ uint32
	var c Count
	var counted bool
	err := attrs(body[4:], func(t uint16, v []byte) error {
		switch t {
		case unix.NFTA_OBJ_TABLE:
			table = cString(v)
		case unix.NFTA_OBJ_NAME:
			name = cString(v)
		case unix.NFTA_OBJ_TYPE:
			if len(v) != 4 {
				return errors.New("netwatch: an object type is malformed")
			}
			typ = binary.BigEndian.Uint32(v)
		case unix.NFTA_OBJ_DATA:
			counted = true
			return attrs(v, func(t uint16, v []byte) error {
				if t != unix.NFTA_COUNTER_BYTES && t != unix.NFTA_COUNTER_PACKETS {
					return nil
				}
				if len(v) != 8 {
					return errors.New("netwatch: a counter is malformed")
				}
				if t == unix.NFTA_COUNTER_BYTES {
					c.Bytes = binary.BigEndian.Uint64(v)
				} else {
					c.Packets = binary.BigEndian.Uint64(v)
				}
				return nil
			})
		}
		return nil
	})
	switch {
	case err != nil:
		return err
	case table != d.table || typ != unix.NFT_OBJECT_COUNTER || name == "" || len(name) > 64:
		return nil
	case !counted:
		return fmt.Errorf("netwatch: counter %q has no counts", name)
	}
	if _, dup := d.out[name]; dup {
		return fmt.Errorf("netwatch: counter %q listed twice", name)
	}
	d.out[name] = c
	if len(d.out) > 256 {
		return errors.New("netwatch: too many counters")
	}
	return nil
}

// attrs calls f with the type and value of each netlink attribute in b.
func attrs(b []byte, f func(typ uint16, val []byte) error) error {
	for len(b) >= unix.SizeofNlAttr {
		size := int(binary.NativeEndian.Uint16(b))
		if size < unix.SizeofNlAttr || size > len(b) {
			return errors.New("netwatch: a netlink attribute is malformed")
		}
		if err := f(binary.NativeEndian.Uint16(b[2:])&^(unix.NLA_F_NESTED|unix.NLA_F_NET_BYTEORDER), b[unix.SizeofNlAttr:size]); err != nil {
			return err
		}
		b = b[min(nlAlign(size), len(b)):]
	}
	return nil
}

func nlAlign(n int) int { return (n + 3) &^ 3 }

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
