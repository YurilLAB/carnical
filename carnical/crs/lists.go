package crs

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// The Core Rule Set keeps its HTTP policy in lists that crs-setup.conf documents as the place to tune it: the request
// content types rule 920420 accepts, and the file extensions rule 920440 refuses. Its own defaults are set by
// REQUEST-901-INITIALIZATION.conf only when nothing set the list first, so a list written here replaces them whole. It is
// built from those defaults as embedded, which keeps a release that changes them from being undone by a copy here.

const (
	// MaxContentTypes and MaxExtensions bound AllowedContentTypes and AllowedExtensions.
	MaxContentTypes = 32
	MaxExtensions   = 32

	contentTypesRuleID = 900220 // the ids crs-setup.conf gives these settings
	rawBodyRuleID      = 900221
	extensionsRuleID   = 900240
	overrideRuleID     = 900250
	blockMarkupRuleID  = 900251 // and 900252
)

// contentTypeShape is a media type without parameters, as rule 920420 compares it (lower case). Nothing in it can end a
// quoted SecLang string or start a macro, and neither a space nor a "|" can join two entries of the list.
var contentTypeShape = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$`)

// IsContentType reports whether t can be one of Settings.AllowedContentTypes.
func IsContentType(t string) bool { return contentTypeShape.MatchString(t) }

// IsRestrictedExtension reports whether ext (".sh") is on the Core Rule Set's list of restricted file extensions, which is
// what Settings.AllowedExtensions may take off it.
func IsRestrictedExtension(ext string) bool {
	d, err := listDefaults()
	return err == nil && strings.HasPrefix(ext, ".") && slices.Contains(strings.Fields(d.extensions), ext+"/")
}

type crsLists struct{ contentTypes, extensions, headers string }

var listDefaults = sync.OnceValues(func() (crsLists, error) {
	b, err := files.ReadFile("owasp_crs/REQUEST-901-INITIALIZATION.conf")
	if err != nil {
		return crsLists{}, err
	}
	get := func(name string) (string, error) {
		m := regexp.MustCompile(`setvar:'tx\.`+name+`=([^'%]*)'`).FindAllSubmatch(b, -1)
		if len(m) != 1 || len(m[0][1]) == 0 {
			return "", fmt.Errorf("the rule set does not set tx.%s once", name)
		}
		return string(m[0][1]), nil
	}
	var l crsLists
	if l.contentTypes, err = get("allowed_request_content_type"); err != nil {
		return l, err
	}
	if l.extensions, err = get("restricted_extensions"); err != nil {
		return l, err
	}
	l.headers, err = get("restricted_headers_basic")
	return l, err
})

func (s Settings) validateLists() error {
	if len(s.AllowedContentTypes) > MaxContentTypes {
		return fmt.Errorf("more than %d allowed content types", MaxContentTypes)
	}
	for _, t := range s.AllowedContentTypes {
		if !IsContentType(t) {
			return fmt.Errorf("content type %q is not a lower-case type/subtype without parameters", t)
		}
	}
	if len(s.AllowedExtensions) > MaxExtensions {
		return fmt.Errorf("more than %d allowed extensions", MaxExtensions)
	}
	if d, err := listDefaults(); err != nil {
		return err
	} else if s.WordPress && !slices.Contains(strings.Fields(d.headers), "/x-http-method-override/") {
		return fmt.Errorf("the rule set no longer restricts X-HTTP-Method-Override as this setting expects")
	}
	for _, ext := range s.AllowedExtensions {
		if !IsRestrictedExtension(ext) {
			return fmt.Errorf("extension %q is not one the Core Rule Set restricts (a dot and lower-case letters, as in .sh)", ext)
		}
	}
	return nil
}

// listDirectives sets the lists the settings change, after crs-setup.conf and before the rules.
func (s Settings) listDirectives() []string {
	d, _ := listDefaults() // validateLists has read them
	var out []string
	if len(s.AllowedContentTypes) > 0 {
		list := d.contentTypes
		for _, t := range s.AllowedContentTypes {
			if !strings.Contains(list, "|"+t+"|") {
				list += " |" + t + "|"
			}
		}
		out = append(out, fmt.Sprintf(`SecAction "id:%d,phase:1,pass,t:none,nolog,setvar:'tx.allowed_request_content_type=%s'"`, contentTypesRuleID, list))
		// A body that no processor claims (JSON and XML types are claimed by base/coraza.conf, forms by the engine) is read
		// whole into REQUEST_BODY, as ModSecurity reads it. Coraza would otherwise parse it as a form, and a binary body
		// such as a git pack would be refused as malformed arguments.
		var added []string
		for _, t := range s.AllowedContentTypes {
			if !strings.Contains(d.contentTypes, "|"+t+"|") {
				added = append(added, regexp.QuoteMeta(t))
			}
		}
		if len(added) > 0 {
			out = append(out, fmt.Sprintf(`SecRule REQBODY_PROCESSOR "@rx ^$" "id:%d,phase:1,pass,t:none,nolog,chain"`, rawBodyRuleID),
				fmt.Sprintf(`SecRule REQUEST_HEADERS:Content-Type "@rx ^(?:%s)\s*(?:;|$)" "t:none,t:lowercase,ctl:requestBodyProcessor=RAW"`, strings.Join(added, "|")))
		}
	}
	if len(s.AllowedExtensions) > 0 {
		var kept []string
		for _, ext := range strings.Fields(d.extensions) {
			if !slices.Contains(s.AllowedExtensions, strings.TrimSuffix(ext, "/")) {
				kept = append(kept, ext)
			}
		}
		out = append(out, fmt.Sprintf(`SecAction "id:%d,phase:1,pass,t:none,nolog,setvar:'tx.restricted_extensions=%s'"`, extensionsRuleID, strings.Join(kept, " ")))
	}
	if s.WordPress {
		// Only on a POST naming a method a REST client tunnels through POST, as the proxy checked; rule 920450 then reads a
		// list without this one header for the request.
		headers := strings.Join(slices.DeleteFunc(strings.Fields(d.headers), func(h string) bool { return h == "/x-http-method-override/" }), " ")
		out = append(out, fmt.Sprintf(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:1,pass,t:none,nolog,chain"`, overrideRuleID),
			fmt.Sprintf(`SecRule REQUEST_HEADERS:X-HTTP-Method-Override "@rx ^(?:PUT|PATCH|DELETE)$" "t:none,setvar:'tx.restricted_headers_basic=%s'"`, headers))
		// The REST API at /wp-json/ in any directory, or through rest_route without pretty links.
		const blockMarkup = "ctl:ruleRemoveTargetById=941180;ARGS:json.content"
		out = append(out, fmt.Sprintf(`SecRule REQUEST_FILENAME "@contains /wp-json/wp/v2/" "id:%d,phase:1,pass,t:none,t:lowercase,nolog,%s"`, blockMarkupRuleID, blockMarkup),
			fmt.Sprintf(`SecRule ARGS_GET:rest_route "@beginsWith /wp/v2/" "id:%d,phase:1,pass,t:none,t:lowercase,nolog,%s"`, blockMarkupRuleID+1, blockMarkup))
	}
	return out
}
