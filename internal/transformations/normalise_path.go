// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"path"
)

func normalisePath(data string) (string, bool, error) {
	leng := len(data)
	if leng < 1 {
		return data, false, nil
	}
	// path, not path/filepath: the result must not depend on the operating system's separator (on Windows
	// filepath.Clean turns "/" into "\\", which stopped rules such as CRS 930120 from matching "etc/passwd").
	clean := path.Clean(data)
	if clean == "." {
		return "", true, nil
	}
	if data[len(data)-1] == '/' {
		result := clean + "/"
		return result, data != result, nil
	}
	return clean, data != clean, nil
}
