// SPDX-License-Identifier: Apache-2.0

package vpatch

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// The data these tests read is the signature library and the replay corpus of the earlier research. It is not part of this
// repository, so a test that needs it is skipped when it is not there. CARNICAL_VPATCH_DATA names the folder that holds
// legacy.jsonl and samples.jsonl, CARNICAL_VPATCH_CORPUS the folder that holds benign.jsonl and attack.jsonl.
func dataPath(t testing.TB, env, def, name string) string {
	t.Helper()
	dir := os.Getenv(env)
	if dir == "" {
		dir = def
	}
	p := filepath.Join(dir, name)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("data file %s not available (set %s)", p, env)
	}
	return p
}

func legacyPath(t testing.TB) string {
	return dataPath(t, "CARNICAL_VPATCH_DATA", filepath.Join("..", "..", ".attack", "sigs"), "legacy.jsonl")
}

func samplesPath(t testing.TB) string {
	return dataPath(t, "CARNICAL_VPATCH_DATA", filepath.Join("..", "..", ".attack", "sigs"), "samples.jsonl")
}

func corpusPath(t testing.TB, name string) string {
	def := filepath.Join("..", "..", "..", "5Weeks1k", "newsletter", "content", "waf", "corpus")
	if _, err := os.Stat("/mnt/d/Dev/5Weeks1k"); err == nil {
		def = "/mnt/d/Dev/5Weeks1k/newsletter/content/waf/corpus"
	}
	return dataPath(t, "CARNICAL_VPATCH_CORPUS", def, name)
}

var (
	libOnce sync.Once
	libSigs []Signature
	libErr  error
)

// library returns the whole signature library (every tier), read once.
func library(t testing.TB) []Signature {
	t.Helper()
	p := legacyPath(t)
	libOnce.Do(func() {
		f, err := os.Open(p)
		if err != nil {
			libErr = err
			return
		}
		defer f.Close()
		libSigs, libErr = ReadLegacy(f)
	})
	if libErr != nil {
		t.Fatal(libErr)
	}
	return libSigs
}

func readSamplesFile(t testing.TB, p string, corpusKind string) []Sample {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []Sample
	if corpusKind == "" {
		out, err = ReadSamples(f)
	} else {
		out, err = ReadCorpus(f, corpusKind)
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}

var allTiers = []string{TierVerified, TierCommunity, TierExperimental}
