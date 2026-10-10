// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/windows"
)

func createSiteFile(root *os.Root, name string) (*os.File, error) {
	if !utf8.ValidString(name) || !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." || strings.TrimRight(name, " .") != name {
		return nil, errors.New("site file requires an unambiguous local filename")
	}
	parent, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	descriptor, err := privateSiteDescriptor(user.User.Sid, false)
	if err != nil {
		return nil, err
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	size := reflect.TypeFor[windows.OBJECT_ATTRIBUTES]().Size()
	if size > math.MaxUint32 {
		return nil, errors.New("file attributes exceed the Windows API size limit")
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		Length:             uint32(size),
		RootDirectory:      windows.Handle(parent.Fd()),
		ObjectName:         objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE,
		SecurityDescriptor: descriptor,
	}
	var handle windows.Handle
	// Set the protected ACL in the creation call. Tightening an inherited ACL
	// later cannot revoke read handles obtained before the change.
	err = windows.NtCreateFile(&handle, windows.FILE_GENERIC_WRITE|windows.FILE_READ_ATTRIBUTES,
		attributes, &windows.IO_STATUS_BLOCK{}, nil, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_CREATE,
		windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	if err != nil {
		if status, ok := err.(windows.NTStatus); ok {
			err = status.Errno()
		}
		return nil, &os.PathError{Op: "create", Path: name, Err: err}
	}
	return os.NewFile(uintptr(handle), filepath.Join(root.Name(), name)), nil
}

func protectSiteFile(file *os.File) error {
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
