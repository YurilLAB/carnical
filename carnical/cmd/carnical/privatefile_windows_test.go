// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// What an account is to a private key. (Its own file: the SIDs are Windows types. The files in
// TestPrivateFilesAreReadWithCare are owned by the account that runs the tests, so they cannot show an owner that is
// someone else.)
func TestAccountsInAKeysAccessList(t *testing.T) {
	const me, owner = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	for _, tt := range []struct {
		name  string
		sid   string
		owner string // "" for the owner above
		want  principal
		as    string // the name it is refused under, when it stands for everyone
	}{
		{"this account", me, "", principalTrusted, ""},
		{"the owner, who is someone else", owner, "", principalTrusted, ""},
		{"SYSTEM", "S-1-5-18", "", principalTrusted, ""},
		{"Administrators", "S-1-5-32-544", "", principalTrusted, ""},
		{"an entry for the owner's rights", "S-1-3-4", "", principalTrusted, ""},
		{"an entry for the creator", "S-1-3-0", "", principalTrusted, ""},
		{"an entry for the creator's group", "S-1-3-1", "", principalTrusted, ""},
		{"another account", "S-1-5-21-1-2-3-1003", "", principalOther, ""},
		{"the network service account", "S-1-5-20", "", principalOther, ""},
		{"the local service account", "S-1-5-19", "", principalOther, ""},
		{"one service", "S-1-5-80-1-2-3-4-5", "", principalOther, ""},
		{"a domain's administrators", "S-1-5-21-1-2-3-512", "", principalOther, ""},
		{"Everyone", "S-1-1-0", "", principalEveryone, "Everyone"},
		{"Authenticated Users", "S-1-5-11", "", principalEveryone, "Authenticated Users"},
		{"Users", "S-1-5-32-545", "", principalEveryone, "Users"},
		{"anonymous logons", "S-1-5-7", "", principalEveryone, "anonymous logons"},
		{"Guests", "S-1-5-32-546", "", principalEveryone, "Guests"},
		{"the Guest account", "S-1-5-21-1-2-3-501", "", principalEveryone, "the Guest account"},
		{"Domain Users", "S-1-5-21-1-2-3-513", "", principalEveryone, "Domain Users"},
		{"Domain Guests", "S-1-5-21-1-2-3-514", "", principalEveryone, "Domain Guests"},
		{"interactive logons", "S-1-5-4", "", principalEveryone, "interactive logons"},
		{"network logons", "S-1-5-2", "", principalEveryone, "network logons"},
		{"batch logons", "S-1-5-3", "", principalEveryone, "batch logons"},
		{"every service", "S-1-5-6", "", principalEveryone, "every service"},
		{"dial-up logons", "S-1-5-1", "", principalEveryone, "dial-up logons"},
		{"remote desktop logons", "S-1-5-14", "", principalEveryone, "remote desktop logons"},
		{"terminal server users", "S-1-5-13", "", principalEveryone, "terminal server users"},
		{"local logons", "S-1-2-0", "", principalEveryone, "local logons"},
		{"console logons", "S-1-2-1", "", principalEveryone, "console logons"},
		{"this organization", "S-1-5-15", "", principalEveryone, "this organization"},
		{"other organizations", "S-1-5-1000", "", principalEveryone, "other organizations"},
		{"every local account", "S-1-5-113", "", principalEveryone, "every local account"},
		{"Power Users", "S-1-5-32-547", "", principalEveryone, "Power Users"},
		{"Remote Desktop Users", "S-1-5-32-555", "", principalEveryone, "Remote Desktop Users"},
		{"Pre-Windows 2000 Compatible Access", "S-1-5-32-554", "", principalEveryone, "Pre-Windows 2000 Compatible Access"},
		{"all application packages", "S-1-15-2-1", "", principalEveryone, "all application packages"},
		// Owning the file does not make everyone trusted.
		{"Everyone, who owns the file", "S-1-1-0", "S-1-1-0", principalEveryone, "Everyone"},
		{"Users, who own the file", "S-1-5-32-545", "S-1-5-32-545", principalEveryone, "Users"},
		// As an access list's text names them.
		{"SYSTEM by its short name", "SY", "", principalTrusted, ""},
		{"Administrators by their short name", "BA", "", principalTrusted, ""},
		{"Everyone by its short name", "WD", "", principalEveryone, "Everyone"},
		{"Users by their short name", "BU", "", principalEveryone, "Users"},
		{"the network service account by its short name", "NS", "", principalOther, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sid := func(s string) *windows.SID {
				v, err := windows.StringToSid(s)
				if err != nil {
					t.Fatalf("%s: %v", s, err)
				}
				return v
			}
			o := owner
			if tt.owner != "" {
				o = tt.owner
			}
			got, as, err := keyHolders{me: sid(me), owner: sid(o)}.kind(tt.sid)
			if err != nil || got != tt.want || as != tt.as {
				t.Fatalf("%s is %v %q (%v), want %v %q", tt.sid, got, as, err, tt.want, tt.as)
			}
		})
	}
	// Who owns the key, whatever its access list says: an owner can always rewrite the list.
	list := []daclEntry{{account: me, mask: 0x001f01ff}, {account: "SY", mask: 0x001f01ff}}
	for _, tt := range []struct {
		name    string
		owner   string
		entries []daclEntry
		problem string // "" if there is none
	}{
		{"this account", me, list, ""},
		{"another account", owner, list, ""},
		{"Administrators", "S-1-5-32-544", list, ""},
		{"SYSTEM", "S-1-5-18", list, ""},
		{"Users", "S-1-5-32-545", list, "must not be owned by Users"},
		{"Everyone", "S-1-1-0", list, "must not be owned by Everyone"},
		{"Authenticated Users", "S-1-5-11", nil, "must not be owned by Authenticated Users"},
		{"a domain's users", "S-1-5-21-1-2-3-513", list, "must not be owned by Domain Users"},
		// With an owner that is fine, the list still decides.
		{"this account, with a list that lets Users read", me, append([]daclEntry{{account: "BU", mask: 0x00120089}}, list...), "must not be accessible to Users"},
		{"another account, with a list that lets a third write", owner, append([]daclEntry{{account: "S-1-5-21-1-2-3-1003", mask: 0x0002}}, list...), "must not be writable by S-1-5-21-1-2-3-1003"},
	} {
		t.Run("owned by "+tt.name, func(t *testing.T) {
			mine, err := windows.StringToSid(me)
			if err != nil {
				t.Fatal(err)
			}
			theirs, err := windows.StringToSid(tt.owner)
			if err != nil {
				t.Fatal(err)
			}
			err = keyHolders{me: mine, owner: theirs}.problem(tt.entries)
			if tt.problem == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.problem) {
				t.Fatalf("%v, want it to say %q", err, tt.problem)
			}
		})
	}
	// A name that is no account is an error, not some other account.
	holders := keyHolders{}
	for _, account := range []string{"", "ZZ", "S-1-x", "sy"} {
		if got, _, err := holders.kind(account); err == nil {
			t.Errorf("%q, which is no account, was taken for one (%v)", account, got)
		}
	}
	// An account as an access list's text names it: a SID, or one of the two-letter names the system knows.
	for _, tt := range []struct {
		account string
		sid     string // "" if it is no account
	}{
		{"SY", "S-1-5-18"}, {"BA", "S-1-5-32-544"}, {"WD", "S-1-1-0"}, {"BU", "S-1-5-32-545"}, {"AU", "S-1-5-11"},
		{"S-1-5-21-1-2-3-1003", "S-1-5-21-1-2-3-1003"},
		{"", ""}, {"S", ""}, {"SYS", ""}, {"sy", ""}, {"S-", ""}, {"S-1-x", ""}, {"B)", ""}, {"ZZ", ""}, {"BAG:SY", ""},
	} {
		got, err := sddlAccount(tt.account)
		if tt.sid == "" {
			if err == nil {
				t.Errorf("%q was read as the account %s", tt.account, got)
			}
			continue
		}
		if err != nil || got.String() != tt.sid {
			t.Errorf("%q is %v (%v), want %s", tt.account, got, err, tt.sid)
		}
	}
}
