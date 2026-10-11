// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// daclEntry is one entry of a Windows access list that allows a principal something on the file itself.
type daclEntry struct {
	account string // as SDDL writes it: an alias (WD, BU) or a SID (S-1-5-...)
	mask    uint32
}

// sddlRights are the access rights a file's access list can carry, by the names SDDL gives them.
var sddlRights = map[string]uint32{
	"GA": 0x10000000, "GX": 0x20000000, "GW": 0x40000000, "GR": 0x80000000,
	"SD": 0x00010000, "RC": 0x00020000, "WD": 0x00040000, "WO": 0x00080000,
	"FA": 0x001f01ff, "FR": 0x00120089, "FW": 0x00120116, "FX": 0x001200a0,
	"CC": 0x0001, "DC": 0x0002, "LC": 0x0004, "SW": 0x0008, "RP": 0x0010, "WP": 0x0020, "DT": 0x0040, "LO": 0x0080, "CR": 0x0100,
}

// daclWrite is the access that changes a file or who may: writing or appending data, rewriting the access list, taking
// ownership, and the generic rights that include them.
const daclWrite = 0x0002 | 0x0004 | 0x00040000 | 0x00080000 | 0x40000000 | 0x10000000

// errNoDACL is a file with no access list at all, which lets everyone do everything.
var errNoDACL = errors.New("a private key must have an access list: without one everyone has full access")

// errDACLUnread is an access list this check cannot read. A private key is not accepted on a guess.
var errDACLUnread = errors.New("the private key's access list cannot be read")

// principal is what an account named in an access list is to a private key.
type principal int

const (
	// principalOther is some other account. It may read, as a file's group may on other systems, and must not write.
	principalOther principal = iota
	// principalTrusted is the account this process runs as, the file's owner, SYSTEM or Administrators.
	principalTrusted
	// principalEveryone stands for whoever is on the machine or the network: Everyone, Users and the like.
	principalEveryone
)

// keyAccessProblem says why an access list lets too many at a private key, or returns nil: an entry for a principal that
// stands for everyone, whatever it allows, or one that lets some other account write. who says what an account is, and
// its name when it stands for everyone.
func keyAccessProblem(entries []daclEntry, who func(account string) (principal, string, error)) error {
	for _, e := range entries {
		kind, name, err := who(e.account)
		switch {
		case err != nil:
			return fmt.Errorf("%w: it names %q", errDACLUnread, e.account)
		case kind == principalEveryone:
			return fmt.Errorf("a private key must not be accessible to %s: take that entry out of its access list (icacls /remove)", name)
		case kind == principalOther && e.mask&daclWrite != 0:
			return fmt.Errorf("a private key must not be writable by %s: its access list lets that account change it", e.account)
		}
	}
	return nil
}

// parseDACL reads the access list of a Windows security descriptor written as SDDL, such as
// "D:PAI(A;;FA;;;SY)(A;ID;0x1200a9;;;BU)", and returns the entries that allow something on the file itself. Entries
// that deny, entries that are only handed down to children, and entries that allow nothing are left out. What it does
// not know (an entry of another kind, a right it cannot name) is an error.
func parseDACL(sddl string) ([]daclEntry, error) {
	rest, ok := strings.CutPrefix(sddl, "D:")
	if !ok {
		return nil, errDACLUnread
	}
	flags := rest
	if i := strings.IndexByte(rest, '('); i >= 0 {
		flags, rest = rest[:i], rest[i:]
	} else {
		rest = ""
	}
	if strings.Contains(flags, "NO_ACCESS_CONTROL") {
		return nil, errNoDACL
	}
	if strings.Trim(flags, "PAIR") != "" { // P, AI and AR say how the list is inherited
		return nil, errDACLUnread
	}
	var out []daclEntry
	for rest != "" {
		end := strings.IndexByte(rest, ')')
		if rest[0] != '(' || end < 0 {
			return nil, errDACLUnread
		}
		f := strings.Split(rest[1:end], ";")
		rest = rest[end+1:]
		// type; flags; rights; object; inherited object; account. A seventh field is a condition, which is not read.
		if len(f) != 6 || f[3] != "" || f[4] != "" || f[5] == "" || strings.ContainsAny(f[5], "() ") {
			return nil, fmt.Errorf("%w: an entry of a kind this check does not know", errDACLUnread)
		}
		switch f[0] {
		case "D": // a denial allows nothing
			continue
		case "A":
		default:
			return nil, fmt.Errorf("%w: an entry of a kind this check does not know (%s)", errDACLUnread, f[0])
		}
		inheritOnly, err := sddlInheritOnly(f[1])
		if err != nil {
			return nil, err
		}
		mask, err := sddlMask(f[2])
		if err != nil {
			return nil, err
		}
		if inheritOnly || mask == 0 {
			continue
		}
		out = append(out, daclEntry{account: f[5], mask: mask})
	}
	return out, nil
}

// sddlInheritOnly reports whether an entry's flags say that it applies to children only (IO), not to the object.
func sddlInheritOnly(flags string) (bool, error) {
	if len(flags)%2 != 0 {
		return false, errDACLUnread
	}
	only := false
	for i := 0; i < len(flags); i += 2 {
		switch flags[i : i+2] {
		case "IO":
			only = true
		case "CI", "OI", "NP", "ID":
		default:
			return false, fmt.Errorf("%w: a flag this check does not know (%s)", errDACLUnread, flags[i:i+2])
		}
	}
	return only, nil
}

// sddlMask reads an entry's rights: a number, or names written one after another.
func sddlMask(rights string) (uint32, error) {
	if rights == "" {
		return 0, nil
	}
	if rights[0] >= '0' && rights[0] <= '9' {
		n, err := strconv.ParseUint(rights, 0, 32)
		if err != nil {
			return 0, errDACLUnread
		}
		return uint32(n), nil
	}
	if len(rights)%2 != 0 {
		return 0, errDACLUnread
	}
	var mask uint32
	for i := 0; i < len(rights); i += 2 {
		bits, ok := sddlRights[rights[i:i+2]]
		if !ok {
			return 0, fmt.Errorf("%w: a right this check does not know (%s)", errDACLUnread, rights[i:i+2])
		}
		mask |= bits
	}
	return mask, nil
}
