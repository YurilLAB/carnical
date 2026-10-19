// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netwatch

import (
	"bytes"
	"encoding/binary"
	"maps"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// What the kernel sends for a dump of the table's counters is read strictly: the table's counters and nothing else,
// and a refusal, a dump the ruleset changed under or a malformed message is an error. (The request itself is checked
// against a real kernel by .github/security/test_network_policy.py.)
func TestCounterDumps(t *testing.T) {
	const seq = 1
	msg := func(typ, flags uint16, seq uint32, body []byte) []byte {
		b := binary.NativeEndian.AppendUint32(nil, uint32(unix.SizeofNlMsghdr+len(body)))
		b = binary.NativeEndian.AppendUint16(b, typ)
		b = binary.NativeEndian.AppendUint16(b, flags)
		b = binary.NativeEndian.AppendUint32(b, seq)
		b = binary.NativeEndian.AppendUint32(b, 0)
		b = append(b, body...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	be64 := func(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }
	counts := func(packets, bytes uint64) []byte {
		return appendAttr(appendAttr(nil, unix.NFTA_COUNTER_BYTES, be64(bytes)), unix.NFTA_COUNTER_PACKETS, be64(packets))
	}
	object := func(table, name string, typ uint32, data []byte) []byte {
		b := []byte{unix.NFPROTO_INET, unix.NFNETLINK_V0, 0, 0}
		b = appendAttr(b, unix.NFTA_OBJ_TABLE, append([]byte(table), 0))
		b = appendAttr(b, unix.NFTA_OBJ_NAME, append([]byte(name), 0))
		b = appendAttr(b, unix.NFTA_OBJ_TYPE, binary.BigEndian.AppendUint32(nil, typ))
		if data != nil {
			b = appendAttr(b, unix.NFTA_OBJ_DATA|unix.NLA_F_NESTED, data)
		}
		return msg(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWOBJ, unix.NLM_F_MULTI, seq, b)
	}
	counter := func(table, name string, packets, bytes uint64) []byte {
		return object(table, name, unix.NFT_OBJECT_COUNTER, counts(packets, bytes))
	}
	status := func(typ uint16, errno int32) []byte {
		return msg(typ, unix.NLM_F_MULTI, seq, binary.NativeEndian.AppendUint32(nil, uint32(errno)))
	}
	done := status(unix.NLMSG_DONE, 0)
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	for _, tc := range []struct {
		name      string
		datagrams [][]byte
		want      map[string]Count
		err       string
	}{
		{name: "the table's counters, not another table's, another kind of object or another request's", datagrams: [][]byte{join(
			counter("carnical", "udp_flood_drop", 400, 36800),
			counter("carnical", "edge_bad_source", 3, 180),
			counter("other_table", "udp_flood_drop", 9, 9),
			object("carnical", "a_quota", 2, counts(1, 1)),
			msg(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWOBJ, unix.NLM_F_MULTI, seq+1, nil),
			done,
		)}, want: map[string]Count{"udp_flood_drop": {400, 36800}, "edge_bad_source": {3, 180}}},
		{name: "a dump over several datagrams", datagrams: [][]byte{
			counter("carnical", "edge_bad_tcp", 1<<62, 1<<63+5), join(counter("carnical", "input_denied", 0, 0), done),
		}, want: map[string]Count{"edge_bad_tcp": {1 << 62, 1<<63 + 5}, "input_denied": {}}},
		{name: "an empty dump", datagrams: [][]byte{done}, want: map[string]Count{}},
		{name: "a refusal", datagrams: [][]byte{status(unix.NLMSG_ERROR, -int32(unix.EPERM))}, err: "operation not permitted"},
		{name: "a dump that ends in an error", datagrams: [][]byte{join(counter("carnical", "x", 1, 1), status(unix.NLMSG_DONE, -int32(unix.EINTR)))}, err: "interrupted"},
		{name: "a ruleset changed while dumped", datagrams: [][]byte{msg(unix.NLMSG_DONE, unix.NLM_F_MULTI|unix.NLM_F_DUMP_INTR, seq, make([]byte, 4))}, err: "changed"},
		{name: "a counter listed twice", datagrams: [][]byte{join(counter("carnical", "x", 1, 1), counter("carnical", "x", 2, 2), done)}, err: "twice"},
		{name: "a counter without counts", datagrams: [][]byte{object("carnical", "x", unix.NFT_OBJECT_COUNTER, nil)}, err: "no counts"},
		{name: "a count cut short", datagrams: [][]byte{object("carnical", "x", unix.NFT_OBJECT_COUNTER, appendAttr(nil, unix.NFTA_COUNTER_BYTES, []byte{1, 2, 3, 4}))}, err: "malformed"},
		{name: "a message longer than its datagram", datagrams: [][]byte{counter("carnical", "x", 1, 1)[:20]}, err: "malformed"},
		{name: "an attribute longer than its message", datagrams: [][]byte{func() []byte {
			b := counter("carnical", "x", 1, 1)
			binary.NativeEndian.PutUint16(b[unix.SizeofNlMsghdr+4:], 0xfff0)
			return b
		}()}, err: "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := counterDump{table: "carnical", seq: seq, out: map[string]Count{}}
			var err error
			for _, b := range tc.datagrams {
				if err = d.add(b); err != nil {
					break
				}
			}
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("%v, want an error with %q", err, tc.err)
				}
				return
			}
			if err != nil || !d.done || !maps.Equal(d.out, tc.want) {
				t.Fatalf("%v %v done=%v, want %v", d.out, err, d.done, tc.want)
			}
		})
	}
}
