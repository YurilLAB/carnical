// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"os"
	"testing"

	"github.com/YurilLAB/coraza/carnical/vpatch/importers"
)

func TestDumpJSONL(t *testing.T) {
	out := os.Getenv("OUT")
	if out == "" {
		t.Skip()
	}
	res, err := Convert(crsDir, importers.Options{Revision: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.Create(out)
	defer f.Close()
	if err := importers.WriteJSONL(f, res.Signatures); err != nil {
		t.Fatal(err)
	}
}
