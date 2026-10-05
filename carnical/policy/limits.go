// SPDX-License-Identifier: Apache-2.0

package policy

// Limits. Every one of these exists because the thing it bounds is attacker-controlled input to a program that holds other
// customers' traffic: a policy comes from a customer, and the edge decodes and compiles it. Where a limit is a count, the
// work done with that many entries is bounded too (a rule is a few kilobytes of SecLang at most, a list is one operator).
const (
	// MaxPolicyBytes is the largest policy document Decode reads.
	MaxPolicyBytes = 1 << 20
	// MaxDepth is how deep a policy document may nest, counting the document itself as 1. The model needs 4.
	MaxDepth = 16
	// MaxStringBytes is the longest string anywhere in a document.
	MaxStringBytes = 8192
	// MaxTokens is the most JSON tokens in a document.
	MaxTokens = 400000

	// MaxSectionBytes, MaxSectionDepth, MaxSectionNodes and MaxSectionKeyBytes bound the sections other packages own (api and
	// body_formats), which are checked here for nothing else.
	MaxSectionBytes    = 256 << 10
	MaxSectionDepth    = 12
	MaxSectionNodes    = 20000
	MaxSectionKeyBytes = 200

	MaxMethods       = 20
	MaxHosts         = 100
	MaxExclusions    = 100
	MaxTargets       = 8
	MaxCustomRules   = 100
	MaxPMValues      = 50
	MaxAllowIPs      = 500
	MaxBlockIPs      = 5000
	MaxAllowPaths    = 200
	MaxDenyHeaders   = 50
	MaxSoftware      = 200
	MaxNoteBytes     = 1000
	MaxItemNoteBytes = 200

	// MaxValueBytes is the longest value of a custom rule (the pattern, for rx); MaxPMValueBytes the longest word of pm.
	MaxValueBytes   = 256
	MaxPMValueBytes = 64
	// MaxRegexCost bounds the size of the program a custom regular expression compiles to (see regexCost).
	MaxRegexCost = 2000
	// MaxPathBytes is the longest exclusion or allowed path.
	MaxPathBytes = 200

	// MinBodyBytes is the smallest body limit; MaxUploadBytesLimit and MaxFormBytesLimit the largest. The upload limit is
	// the one that costs memory, because a file upload is read whole before it is looked at, once for every request in
	// flight: 64 MiB keeps even a hundred of them within what one edge can hold. A body that is not an upload costs time, not
	// memory, in proportion to its size, and the evaluation budget cuts it off, so 1 MiB is already more than it can use.
	MinBodyBytes        = 1 << 10
	MaxUploadBytesLimit = 64 << 20
	MaxFormBytesLimit   = 1 << 20

	DefaultUploadBytes = 1 << 20
	DefaultFormBytes   = 128 << 10

	// MaxLineBytes is the longest line of SecLang this package will write. The parser reads lines with a 64 KiB limit and
	// stops, without an error, at the first line over it, which would silently drop every directive after it.
	MaxLineBytes = 32 << 10
)

// The reserved range of rule ids in the generated SecLang (1000000 to 1099999), and how it is divided.
const (
	idBase       = 1000000
	idLimit      = 1099999
	idExclusions = 1010000 // + 100 * the exclusion's position + the category's position
	idAllowIPs   = 1020000 // + the chunk
	idBlockIPs   = 1030000 // + the chunk
	idAllowPaths = 1040000 // + the path's position
	idCustom     = 1050000 // + the rule's ID
)
