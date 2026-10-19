// SPDX-License-Identifier: Apache-2.0

package netwatch

import (
	"encoding/json"
	"errors"
	"fmt"
)

// MaxListing is the most bytes of nft's JSON that are read: the counters are a few kilobytes and the sets hold at most
// 2,560 elements.
const MaxListing = 4 << 20

// maxElements bounds the elements read from one set listing.
const maxElements = 8192

type nftDoc struct {
	Nftables []map[string]json.RawMessage `json:"nftables"`
}

type nftCounter struct {
	Name    string `json:"name"`
	Table   string `json:"table"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// ParseCounters reads the output of `nft -j list counters table inet carnical`: each named counter of the table.
func ParseCounters(data []byte, table string) (map[string]Count, error) {
	doc, err := parse(data)
	if err != nil {
		return nil, err
	}
	out := map[string]Count{}
	for _, item := range doc.Nftables {
		raw, ok := item["counter"]
		if !ok {
			continue
		}
		var c nftCounter
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, errors.New("netwatch: a counter cannot be read")
		}
		if c.Table != table || c.Name == "" || len(c.Name) > 64 {
			continue
		}
		if _, dup := out[c.Name]; dup {
			return nil, fmt.Errorf("netwatch: counter %q listed twice", c.Name)
		}
		out[c.Name] = Count{Packets: c.Packets, Bytes: c.Bytes}
		if len(out) > 256 {
			return nil, errors.New("netwatch: too many counters")
		}
	}
	return out, nil
}

type nftSet struct {
	Name  string            `json:"name"`
	Table string            `json:"table"`
	Type  string            `json:"type"`
	Size  int               `json:"size"`
	Elem  []json.RawMessage `json:"elem"`
}

type nftElem struct {
	Elem struct {
		Val     json.RawMessage `json:"val"`
		Counter *nftCounter     `json:"counter"`
	} `json:"elem"`
}

// ParseSet reads the output of `nft -j list set inet carnical NAME` for a set of ports with counters: each port and
// what it counted, and whether the set holds as many as it can. An element without a counter, or whose value is not a
// port, is an error: the policy is not the one this reads. Port 0 is a port: a datagram can be sent to it.
func ParseSet(data []byte, table, name string) (map[uint16]Count, bool, error) {
	doc, err := parse(data)
	if err != nil {
		return nil, false, err
	}
	for _, item := range doc.Nftables {
		raw, ok := item["set"]
		if !ok {
			continue
		}
		var s nftSet
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, false, errors.New("netwatch: a set cannot be read")
		}
		if s.Table != table || s.Name != name {
			continue
		}
		if s.Type != "inet_service" {
			return nil, false, fmt.Errorf("netwatch: set %s is not of ports", name)
		}
		if len(s.Elem) > maxElements {
			return nil, false, fmt.Errorf("netwatch: set %s has more than %d elements", name, maxElements)
		}
		out := make(map[uint16]Count, len(s.Elem))
		for _, raw := range s.Elem {
			var e nftElem
			if err := json.Unmarshal(raw, &e); err != nil || e.Elem.Counter == nil {
				return nil, false, fmt.Errorf("netwatch: set %s has an element without a counter", name)
			}
			var port uint16
			if err := json.Unmarshal(e.Elem.Val, &port); err != nil {
				return nil, false, fmt.Errorf("netwatch: set %s has an element that is not a port", name)
			}
			out[port] = Count{Packets: e.Elem.Counter.Packets, Bytes: e.Elem.Counter.Bytes}
		}
		return out, s.Size > 0 && len(out) >= s.Size, nil
	}
	return nil, false, fmt.Errorf("netwatch: set %s is not listed", name)
}

func parse(data []byte) (*nftDoc, error) {
	if len(data) > MaxListing {
		return nil, fmt.Errorf("netwatch: nft listing larger than %d bytes", MaxListing)
	}
	var doc nftDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, errors.New("netwatch: nft listing is not JSON")
	}
	return &doc, nil
}
