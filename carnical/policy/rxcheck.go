// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The text of a custom rule's value reaches the engine inside a SecLang line:
//
//	SecRule ARGS "@rx TEXT" "id:...,..."
//
// where the quotes, the backslash, the percent sign (which starts a macro) and white space all mean something to the
// SecLang reader, and where the engine itself decides, by looking at the backslash escapes in TEXT, whether to match runes
// or raw bytes. This file is the one place that text is made. It makes it in a way that cannot go wrong by escaping
// carefully: it never writes the customer's text at all. Every operator is written as a regular expression built from a
// parsed regular expression tree, and the text that comes out is checked, after it is made, to use only characters that
// mean nothing to SecLang. A character that cannot be written safely makes the rule an error; it is never dropped or changed.

const engineFlags = "(?sm)" // what the engine puts in front of every @rx pattern (internal/operators/rx.go)

// literalRx writes the text s as an RE2 expression that matches exactly s, and nothing else.
//
//   - letters and digits are written as they are;
//   - every other ASCII character is written \xHH, so a quote, a backslash, a space, a percent sign, a brace, a bracket and a
//     control character are all the same plain thing: two hex digits;
//   - a character outside ASCII is written as itself if it is printable (a letter, mark, number, punctuation, symbol), because
//     \x escapes above 0x7f make the engine match raw bytes and not text; one that is not printable (a control character, a
//     line or paragraph separator, a bidirectional override, a zero-width character, a non-breaking space) is an error.
func literalRx(s string) (string, error) {
	if s == "" {
		return "", errors.New("is empty")
	}
	if !utf8.ValidString(s) {
		return "", errors.New("is not valid UTF-8 text")
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r < 0x80:
			fmt.Fprintf(&b, `\x%02x`, r)
		case unicode.IsPrint(r):
			b.WriteRune(r)
		default:
			return "", errors.New("holds a character that cannot be written safely (a control, separator, invisible or direction-changing character)")
		}
	}
	return b.String(), nil
}

// canonRx makes the text of a customer's regular expression safe to put in a rule, without changing what it matches. It
// parses the expression the way the engine will read it (RE2, with the engine's flags in front), refuses one that is too
// big, writes the parsed tree back out in the library's canonical spelling with the five characters SecLang cares about
// (quote, apostrophe, percent sign, space, backtick) and a literal backslash as \x escapes, and checks that this parses back
// to the same tree. The result is checked as every rule's text is (checkEmittable).
func canonRx(pattern string) (string, error) {
	if pattern == "" {
		return "", errors.New("is empty")
	}
	if len(pattern) > MaxValueBytes {
		return "", fmt.Errorf("is longer than %d bytes", MaxValueBytes)
	}
	if !utf8.ValidString(pattern) {
		return "", errors.New("is not valid UTF-8 text")
	}
	re, err := syntax.Parse(engineFlags+pattern, syntax.Perl)
	if err != nil {
		return "", fmt.Errorf("is not a valid regular expression (RE2 syntax): %s", syntaxCode(err))
	}
	if cost := regexCost(re); cost > MaxRegexCost {
		return "", fmt.Errorf("is too large a regular expression (%d, at most %d): fewer or smaller repeats are needed", cost, MaxRegexCost)
	}
	// The estimate counts an optional copy of a{n,m} once, where the compiler writes a branch as well, so the program itself is
	// counted too: its size is what bounds the time a match can take (see MaxRegexCost).
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return "", errors.New("does not compile")
	}
	if len(prog.Inst) > MaxRegexCost {
		return "", fmt.Errorf("compiles to a program of %d instructions, more than %d: fewer or smaller repeats are needed", len(prog.Inst), MaxRegexCost)
	}
	canon := re.String()
	var b strings.Builder
	for i := 0; i < len(canon); {
		r, size := utf8.DecodeRuneInString(canon[i:])
		switch {
		case r == '\\' && i+1 < len(canon) && canon[i+1] == '\\':
			// A literal backslash. The engine's test for byte escapes (engineReadsBytes) takes each backslash on its own, so in
			// "\\x90" it would see the escape \x90, a byte that is not UTF-8, and match the whole expression as raw bytes. \x5c is
			// the same backslash to RE2 and nothing to that test.
			b.WriteString(`\x5c`)
			i += 2
			continue
		case r == '\\' && i+1 < len(canon):
			// Any other escape is copied whole, so that the character after the backslash is never read as one of its own.
			_, n := utf8.DecodeRuneInString(canon[i+1:])
			b.WriteString(canon[i : i+1+n])
			i += 1 + n
			continue
		case r == '"', r == '\'', r == '%', r == ' ', r == '`':
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	out := b.String()
	back, err := syntax.Parse(engineFlags+out, syntax.Perl)
	if err != nil || !back.Equal(re) {
		return "", errors.New("cannot be written back out exactly; write it more plainly")
	}
	if err := checkEmittable(out); err != nil {
		return "", err
	}
	return out, nil
}

// syntaxCode is the kind of syntax error, without the text of the expression (which the library's message quotes).
func syntaxCode(err error) string {
	var se *syntax.Error
	if errors.As(err, &se) {
		return string(se.Code)
	}
	return "invalid"
}

// regexCost is how many instructions an expression compiles to, counted without building them: a repeat multiplies the cost of
// what it repeats, so (a{100}){100} costs 10,000 before anything is expanded. The count saturates, so it cannot overflow.
func regexCost(re *syntax.Regexp) int {
	const limit = 1 << 30
	add := func(a, b int) int {
		if a+b > limit {
			return limit
		}
		return a + b
	}
	mul := func(a, b int) int {
		if b != 0 && a > limit/b {
			return limit
		}
		return a * b
	}
	switch re.Op {
	case syntax.OpLiteral:
		return len(re.Rune)
	case syntax.OpCharClass:
		return 1 + len(re.Rune)/32
	case syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		return add(regexCost(re.Sub[0]), 1)
	case syntax.OpRepeat:
		n := re.Max
		if n < 0 {
			n = re.Min + 1
		}
		if n < 1 {
			n = 1
		}
		return add(mul(n, regexCost(re.Sub[0])), 1)
	case syntax.OpConcat, syntax.OpAlternate:
		c := 1
		for _, s := range re.Sub {
			c = add(c, regexCost(s))
		}
		return c
	}
	return 1
}

// checkEmittable is the last check on the text of an @rx pattern before it is written into a rule. It must be one thing:
// printable characters that mean nothing to SecLang. No control character, space, quote, apostrophe or percent sign, every
// backslash followed by something, no \x escape above 0x7f and no \x{...} (the engine reads those as raw bytes), nothing
// the engine's own test for byte escapes reads as raw bytes (engineReadsBytes), and the result compiles with the engine's flags.
func checkEmittable(s string) error {
	if len(s) > MaxLineBytes/2 {
		return errors.New("is too long once written out")
	}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			return errors.New("holds text that is not valid UTF-8 once written out")
		case r <= 0x20 || r == 0x7f || r == '"' || r == '\'' || r == '%' || r == '`':
			return errors.New("holds a character that cannot be written safely")
		case r >= 0x80 && !unicode.IsPrint(r):
			return errors.New("holds a character that cannot be written safely")
		case r == '\\':
			if i+1 >= len(s) {
				return errors.New("ends in a lone backslash")
			}
			if s[i+1] >= 0x80 {
				return errors.New("holds a backslash before a character outside ASCII")
			}
			if s[i+1] == 'x' && (i+3 >= len(s) || !isHex(s[i+2]) || !isHex(s[i+3]) || hexVal(s[i+2]) >= 8) {
				return errors.New("needs a character above 0x7f that cannot be written safely (an invisible, separator or direction-changing character, or a negated class such as [^\\x00-\\x7f]): write letters and symbols as themselves, or use \\p{...} classes")
			}
			i += 2
			continue
		}
		i += size
	}
	if engineReadsBytes(engineFlags + s) {
		return errors.New("would be matched by the engine as raw bytes and not as text (it reads a backslash, x and two hex digits from 80 to ff as a byte, even after another backslash)")
	}
	if _, err := regexp.Compile(engineFlags + s); err != nil {
		return errors.New("does not compile once written out")
	}
	return nil
}

// engineReadsBytes is the engine's own test of whether an @rx pattern is matched as raw bytes (matchesArbitraryBytes in
// internal/operators/rx.go), repeated here step for step so that checkEmittable refuses what the engine would read that way.
// It reads each backslash on its own and does not know an escaped one: to it, "\\x90" is a backslash and then the escape \x90,
// the byte 0x90, which is not UTF-8, so the engine would compile the whole expression to match bytes and a letter outside
// ASCII in it would stop matching text.
func engineReadsBytes(expr string) bool {
	decoded := make([]byte, 0, len(expr))
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c != '\\' {
			decoded = append(decoded, c)
			continue
		}
		if i+3 >= len(expr) {
			decoded = append(decoded, expr[i:]...)
			break
		}
		if expr[i+1] != 'x' {
			decoded = append(decoded, expr[i])
			continue
		}
		sub := expr[i:]
		advance := 3
		if len(sub) >= 6 && sub[2] == '{' {
			if end := strings.IndexByte(sub, '}'); end != -1 {
				sub = `\x` + sub[3:end]
				advance = end
			}
		}
		v, multibyte, _, err := strconv.UnquoteChar(sub, 0)
		if err != nil || multibyte || v < 0 || v > 255 {
			decoded = append(decoded, expr[i])
			continue
		}
		decoded = append(decoded, byte(v))
		i += advance
	}
	return !utf8.Valid(decoded)
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) int {
	switch {
	case c >= 'a':
		return int(c-'a') + 10
	case c >= 'A':
		return int(c-'A') + 10
	}
	return int(c - '0')
}

// operatorRegex is the regular expression text a custom rule's operator and value are compiled to. Every operator is a regular
// expression, so that the text that reaches SecLang is always one of the two things above and never the customer's own.
func operatorRegex(op Operator, value string, words []string, caseSensitive bool) (string, error) {
	var body string
	switch op {
	case OpContains, OpEquals, OpBeginsWith, OpEndsWith:
		lit, err := literalRx(value)
		if err != nil {
			return "", err
		}
		switch op {
		case OpContains:
			body = lit
		case OpEquals:
			body = `\A` + lit + `\z`
		case OpBeginsWith:
			body = `\A` + lit
		case OpEndsWith:
			body = lit + `\z`
		}
	case OpPM:
		if len(words) == 0 {
			return "", errors.New("needs at least one word")
		}
		alts := make([]string, len(words))
		for i, w := range words {
			lit, err := literalRx(w)
			if err != nil {
				return "", fmt.Errorf("word %d %s", i+1, err)
			}
			alts[i] = lit
		}
		body = "(?:" + strings.Join(alts, "|") + ")"
	case OpRX:
		c, err := canonRx(value)
		if err != nil {
			return "", err
		}
		// Grouped, so that the text never ends in a backslash: a quotation mark that follows a backslash is never written, even
		// when the engine would read it as the end of the operator (after an escaped backslash).
		body = "(?:" + c + ")"
	default:
		return "", errors.New("is not an operator")
	}
	if !caseSensitive {
		body = "(?i:" + body + ")"
	}
	if err := checkEmittable(body); err != nil {
		return "", err
	}
	return body, nil
}
