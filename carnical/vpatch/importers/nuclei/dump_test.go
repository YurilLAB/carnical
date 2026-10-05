// SPDX-License-Identifier: Apache-2.0

package nuclei

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
	res, err := Convert(upstreamDir, importers.Options{Revision: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.Create(out)
	defer f.Close()
	if err := importers.WriteJSONL(f, res.Signatures); err != nil {
		t.Fatal(err)
	}
}
