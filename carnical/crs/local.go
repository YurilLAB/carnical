// SPDX-License-Identifier: Apache-2.0

package crs

// stricterLocalRules are in the rule file like the others and score nothing unless Settings.LocalRulesOn names them.
var stricterLocalRules = [...]int{5006101, 5006102, 5006103}

func isStricterLocalRule(id int) bool {
	for _, s := range stricterLocalRules {
		if s == id {
			return true
		}
	}
	return false
}

// LocalRuleMessage returns a fixed, request-independent label for a local rule.
// Do not use a rule's macro-expanded message in a default log.
func LocalRuleMessage(id int) string {
	switch id {
	case 5006001:
		return "XPath predicate injection syntax"
	case 5006002:
		return "XPath union injection syntax"
	case 5006003:
		return "Shell command chaining or substitution"
	case 5006004:
		return "Command interpreter invocation"
	case 5006005:
		return "Server template expression injection"
	case 5006006:
		return "Nested-encoded parent path traversal"
	case 5006007:
		return "Java serialization stream in a request field"
	case 5006008:
		return "Unsafe fetch protocol or ambiguous URL authority"
	case 5006009:
		return "XPath comment obfuscation after a quote"
	case 5006010:
		return "Obfuscated shell command spelling"
	case 5006011:
		return "Exploit or web shell path"
	case 5006012:
		return "Debug or diagnostic interface"
	case 5006013:
		return "Web application installer"
	case 5006014:
		return "Scanner user agent"
	case 5006015:
		return "Remote file reference in an include parameter"
	case 5006016:
		return "FTP, SMB or scheme-less reference to another host"
	case 5006017:
		return "Remote text or include file URL"
	case 5006018:
		return "Database administration tool"
	case 5006019:
		return "PHP information or test page"
	case 5006020:
		return "Debugger or server console"
	case 5006021:
		return "Script on another host in a URL parameter"
	case 5006022:
		return "Forwarded host header that is not a host name"
	case 5006023:
		return "Unicode newline header injection (response splitting)"
	case 5006101:
		return "Console path"
	case 5006102:
		return "Script on another host in a body parameter"
	case 5006103:
		return "Forwarded host that is not the host asked for"
	default:
		return ""
	}
}
