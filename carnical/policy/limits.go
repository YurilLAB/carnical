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
	// MaxRegexCost bounds the program a custom regular expression compiles to, in instructions: worked out from the parsed
	// tree before anything is built (see regexCost), then counted in the compiled program. It bounds time as much as size. The
	// engine matches with an automaton whose worst case keeps every instruction alive at every byte it reads, and the
	// evaluation budget is checked between rules, so it cannot stop one expression. Measured on the shared 4-CPU test machine
	// that is about 11 ns per instruction per byte: at 256 one expression costs at most about 3.5 s on a 1 MiB body (the
	// largest form limit) and under 0.5 s on the default 128 KiB, the order of the 2 s budget and the same as a contains rule
	// with the longest value (256 bytes, case ignored: 3.4 s on 1 MiB); at 2,000 it was 22 s. 256 still takes a list of some
	// 30 words, a credit-card or token pattern, or a run such as [A-Za-z0-9+/]{200,}; a longer list is what pm is for.
	MaxRegexCost = 256
	// MaxClassFolding bounds the code points of a custom regular expression's character classes that are case-folded one at a
	// time when it is read case-insensitively (see classFolding), about 25 ns each, so that checking or loading one costs a few
	// milliseconds at most. It takes three \pL (66,000 each, the widest class in common use); [^/] and \w cost next to nothing.
	MaxClassFolding = 1 << 18
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
