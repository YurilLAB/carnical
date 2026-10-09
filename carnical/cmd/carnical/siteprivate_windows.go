// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func protectSiteFile(file *os.File) error {
	// os.OpenFile does not request WRITE_DAC. Reopen the empty file with the
	// required rights and verify identity before changing its ACL. Never secure
	// a path then assume that the original open handle refers to that path.
	path, err := windows.UTF16PtrFromString(file.Name())
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(path, windows.WRITE_DAC|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	aclFile := os.NewFile(uintptr(handle), file.Name())
	defer aclFile.Close()
	original, err := file.Stat()
	if err != nil {
		return err
	}
	reopened, err := aclFile.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(original, reopened) {
		return errors.New("site file changed while protecting its ACL")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := privateSiteDescriptor(user.User.Sid, false)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}
	return checkPrivateSiteFile(file)
}

func checkPrivateSiteFile(file *os.File) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	// Accept only the explicit current-user and SYSTEM full-access entries made
	// above. Fail closed on inherited, missing, null or additional grants. SDDL
	// avoids unsafe ACE/SID pointer arithmetic in application code.
	expected, err := privateSiteDescriptor(user.User.Sid, false)
	if err != nil {
		return err
	}
	text := strings.Replace(sd.String(), "D:PAI(", "D:P(", 1)
	if text != expected.String() {
		otherOrder, err := privateSiteDescriptor(user.User.Sid, true)
		if err != nil {
			return err
		}
		if text != otherOrder.String() {
			return errors.New("site encryption key requires a protected ACL granting access only to the current user and SYSTEM")
		}
	}
	return nil
}

func privateSiteDescriptor(user *windows.SID, systemFirst bool) (*windows.SECURITY_DESCRIPTOR, error) {
	system := "(A;;FA;;;SY)"
	if user.IsWellKnown(windows.WinLocalSystemSid) {
		return windows.SecurityDescriptorFromString("D:P" + system)
	}
	account := "(A;;FA;;;" + user.String() + ")"
	if systemFirst {
		return windows.SecurityDescriptorFromString("D:P" + system + account)
	}
	return windows.SecurityDescriptorFromString("D:P" + account + system)
}
