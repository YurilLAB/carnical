// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// everyone is the principals that stand for whoever is on the machine or the network. An entry for one of them, with
// any access at all, is what "readable by everyone" means on Windows.
var everyone = []struct {
	kind windows.WELL_KNOWN_SID_TYPE
	name string
}{
	{windows.WinWorldSid, "Everyone"},
	{windows.WinAuthenticatedUserSid, "Authenticated Users"},
	{windows.WinBuiltinUsersSid, "Users"},
	{windows.WinAnonymousSid, "anonymous logons"},
	{windows.WinBuiltinGuestsSid, "Guests"},
	{windows.WinAccountGuestSid, "the Guest account"},
	{windows.WinAccountDomainUsersSid, "Domain Users"},
	{windows.WinAccountDomainGuestsSid, "Domain Guests"},
	{windows.WinInteractiveSid, "interactive logons"},
	{windows.WinNetworkSid, "network logons"},
	{windows.WinBatchSid, "batch logons"},
	{windows.WinServiceSid, "every service"},
	{windows.WinDialupSid, "dial-up logons"},
	{windows.WinRemoteLogonIdSid, "remote desktop logons"},
	{windows.WinTerminalServerSid, "terminal server users"},
	{windows.WinLocalSid, "local logons"},
	{windows.WinConsoleLogonSid, "console logons"},
	{windows.WinLocalLogonSid, "local logons"},
	{windows.WinThisOrganizationSid, "this organization"},
	{windows.WinOtherOrganizationSid, "other organizations"},
	{windows.WinLocalAccountSid, "every local account"},
	{windows.WinBuiltinPowerUsersSid, "Power Users"},
	{windows.WinBuiltinRemoteDesktopUsersSid, "Remote Desktop Users"},
	{windows.WinBuiltinPreWindows2000CompatibleAccessSid, "Pre-Windows 2000 Compatible Access"},
	{windows.WinBuiltinAnyPackageSid, "all application packages"},
}

// privateFileAccess says why a private key's access list lets too many at it, or returns nil. It is the counterpart of
// the mode test made on other systems (nothing for everyone, no writing for the group): see keyAccessProblem. The list is
// read as text (SDDL), which needs no pointer arithmetic over its entries.
func privateFileAccess(f *os.File) error {
	h := windows.Handle(f.Fd())
	dacl, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%w: %v", errDACLUnread, err)
	}
	entries, err := parseDACL(dacl.String())
	if err != nil {
		return err
	}
	owned, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%w: %v", errDACLUnread, err)
	}
	owner, _, err := owned.Owner()
	if err != nil {
		return fmt.Errorf("%w: %v", errDACLUnread, err)
	}
	if owner == nil {
		return fmt.Errorf("%w: the file has no owner", errDACLUnread)
	}
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("%w: %v", errDACLUnread, err)
	}
	return keyHolders{me: me.User.Sid, owner: owner}.problem(entries)
}

// keyHolders are the two accounts a private key belongs to: the one that reads it and the one that owns the file.
type keyHolders struct{ me, owner *windows.SID }

// problem says why the key's owner or its access list lets too many at it, or returns nil. An owner can always rewrite
// the access list, whatever the list says, so a key that a principal standing for everyone owns is everyone's.
func (k keyHolders) problem(entries []daclEntry) error {
	if name := standsForEveryone(k.owner); name != "" {
		return fmt.Errorf("a private key must not be owned by %s: an owner can always rewrite its access list (icacls /setowner)", name)
	}
	return keyAccessProblem(entries, k.kind)
}

// standsForEveryone names the principal a SID is when it stands for whoever is on the machine or the network, or
// returns "".
func standsForEveryone(sid *windows.SID) string {
	for _, w := range everyone {
		if sid.IsWellKnown(w.kind) {
			return w.name
		}
	}
	return ""
}

// kind says what an account, as an access list's text names it, is to the key. What stands for everyone does so whoever
// else it is: a key owned by Users is not a key that Users may have.
func (k keyHolders) kind(account string) (principal, string, error) {
	sid, err := sddlAccount(account)
	if err != nil {
		return principalOther, "", err
	}
	if name := standsForEveryone(sid); name != "" {
		return principalEveryone, name, nil
	}
	// The owner may write, as on other systems, and an entry for "the owner", whoever that is, is the owner's.
	if sid.Equals(k.me) || sid.Equals(k.owner) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) || sid.IsWellKnown(windows.WinCreatorOwnerSid) || sid.IsWellKnown(windows.WinCreatorGroupSid) {
		return principalTrusted, "", nil
	}
	return principalOther, "", nil
}

// sddlAccount turns an account as SDDL writes it into a SID. An alias is resolved by the system, as the owner of a
// descriptor that says nothing else.
func sddlAccount(account string) (*windows.SID, error) {
	if strings.HasPrefix(account, "S-") {
		return windows.StringToSid(account)
	}
	if len(account) != 2 || strings.Trim(account, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		return nil, errors.New("not an account")
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + account)
	if err != nil {
		return nil, err
	}
	sid, _, err := sd.Owner()
	return sid, err
}
