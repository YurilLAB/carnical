// SPDX-License-Identifier: Apache-2.0

package formats

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"
)

// MaxPolicyBytes bounds JSON policy loading in the library and executable.
const MaxPolicyBytes = 1 << 20

// Policy is what a site accepts. It is plain data that can be written as JSON; a field left out (or zero) takes the default shown
// beside it, so a policy only names what differs. Nothing can be switched to "unlimited": a limit is a positive number below a fixed
// ceiling, because the point of every limit is that the cost of a request is bounded by its size.
type Policy struct {
	// Monitor records every finding and refuses nothing. Start a site here, read what is found, then turn it off.
	Monitor bool `json:"monitor,omitempty"`
	// Rules changes what happens for a named rule: "block", "monitor" or "off". The names and their defaults are in docs/formats.md. An
	// unknown name is an error, so a misspelt rule can never leave a protection quietly on its default.
	Rules map[string]Action `json:"rules,omitempty"`

	// AllowedTypes are the media types accepted. An entry is "type/subtype", "type/*", or "*+suffix" (such as "*+json"). Default:
	// application/x-www-form-urlencoded, multipart/form-data, application/json, *+json, application/xml, text/xml, *+xml,
	// application/graphql, application/x-ndjson, application/jsonl, text/plain. YAML is not in the list: add application/yaml,
	// text/yaml and application/x-yaml to accept it.
	AllowedTypes []string `json:"allowed_types,omitempty"`
	// AllowOpaque lists binary types (msgpack, CBOR, protobuf, gRPC, octet-stream) the site really receives. Nothing can inspect them,
	// so they are refused unless named here, and then only up to OpaqueMaxBytes. An entry is a media type or a prefix ending in "*"
	// (such as "application/grpc*").
	AllowOpaque []string `json:"allow_opaque,omitempty"`
	// OpaqueMaxBytes is the largest opaque body accepted (default 65536).
	OpaqueMaxBytes int `json:"opaque_max_bytes,omitempty"`
	// AllowedCharsets are the charset parameters accepted (default utf-8, us-ascii, iso-8859-1, windows-1252). UTF-16 and UTF-32 are how
	// a filter is made to skip a body.
	AllowedCharsets []string `json:"allowed_charsets,omitempty"`
	// MaxBodyBytes is the largest body accepted after any decompression (default 1 MiB).
	MaxBodyBytes int `json:"max_body_bytes,omitempty"`
	// MaxQueryBytes is the largest raw URL query inspected (default 65536); server request-target limits also apply.
	MaxQueryBytes int `json:"max_query_bytes,omitempty"`
	// GraphQLPaths names paths (exact, as received) that are GraphQL endpoints, in addition to any path with a segment called graphql or
	// graphiql. A request to one is checked as GraphQL; a request elsewhere is checked only if its query parses as GraphQL.
	GraphQLPaths []string `json:"graphql_paths,omitempty"`

	JSON      JSONLimits      `json:"json"`
	XML       XMLLimits       `json:"xml"`
	GraphQL   GraphQLLimits   `json:"graphql"`
	NDJSON    NDJSONLimits    `json:"ndjson"`
	Encoding  EncodingLimits  `json:"encoding"`
	YAML      YAMLLimits      `json:"yaml"`
	Form      FormLimits      `json:"form"`
	Query     FormLimits      `json:"query"`
	Multipart MultipartLimits `json:"multipart"`
}

// JSONLimits bound a JSON document. The parser is strict RFC 8259 whatever these are.
type JSONLimits struct {
	MaxDepth     int `json:"max_depth,omitempty"`      // nesting of arrays and objects (default 64)
	MaxNodes     int `json:"max_nodes,omitempty"`      // values of every kind (default 50000)
	MaxKeys      int `json:"max_keys,omitempty"`       // object members, all objects together (default 20000)
	MaxKeyLen    int `json:"max_key_len,omitempty"`    // bytes in a key, escapes not decoded (default 1024)
	MaxStringLen int `json:"max_string_len,omitempty"` // bytes in a string, escapes not decoded (default 262144)
	MaxNumberLen int `json:"max_number_len,omitempty"` // bytes in a number (default 64)
}

// XMLLimits bound an XML document.
type XMLLimits struct {
	MaxDepth        int `json:"max_depth,omitempty"`          // open elements (default 32)
	MaxAttributes   int `json:"max_attributes,omitempty"`     // on one element (default 64)
	MaxElements     int `json:"max_elements,omitempty"`       // elements in the document (default 50000)
	MaxNameLen      int `json:"max_name_len,omitempty"`       // bytes in an element or attribute name (default 256)
	MaxAttrValueLen int `json:"max_attr_value_len,omitempty"` // bytes in an attribute value (default 65536)
	MaxTextLen      int `json:"max_text_len,omitempty"`       // bytes in one run of text (default 262144)
}

// GraphQLLimits bound a GraphQL query. Depth, fields, aliases and directives are counted after fragments are expanded, because a
// fragment spread several times is work done several times.
type GraphQLLimits struct {
	MaxDepth      int `json:"max_depth,omitempty"`       // nesting of selection sets (default 12)
	MaxFields     int `json:"max_fields,omitempty"`      // fields selected in one operation (default 500)
	MaxAliases    int `json:"max_aliases,omitempty"`     // aliases in one operation (default 20)
	MaxDirectives int `json:"max_directives,omitempty"`  // directives in one operation (default 50)
	MaxBatch      int `json:"max_batch,omitempty"`       // operations in a JSON array (default 10)
	MaxOperations int `json:"max_operations,omitempty"`  // operations in one document (default 10)
	MaxQueryBytes int `json:"max_query_bytes,omitempty"` // bytes in one document (default 65536)
	// Request totals count the selected operation of every document in the request, with fragments expanded.
	MaxRequestFields     int `json:"max_request_fields,omitempty"`     // default 1000
	MaxRequestAliases    int `json:"max_request_aliases,omitempty"`    // default 40
	MaxRequestDirectives int `json:"max_request_directives,omitempty"` // default 100
	// AllowIntrospection lets __schema and __type through. Introspection hands an attacker the whole schema.
	AllowIntrospection bool `json:"allow_introspection,omitempty"`
}

// NDJSONLimits bound a newline-delimited JSON body. Each line is a strict JSON document under the JSON limits; the node and key
// counts are for the whole body.
type NDJSONLimits struct {
	MaxLines int `json:"max_lines,omitempty"` // default 1000
}

// EncodingLimits bound the decompression of a gzip or deflate request body.
type EncodingLimits struct {
	MaxOutput int `json:"max_output,omitempty"` // bytes after decompression (default 1 MiB)
	MaxRatio  int `json:"max_ratio,omitempty"`  // output bytes per input byte (default 100); small outputs are exempt, see docs
	// AllowRawDeflate also accepts a deflate body with no zlib header. RFC 9110 says "deflate" is zlib, but some clients send it raw,
	// and a body one side reads as zlib and the other as raw is a differential.
	AllowRawDeflate bool `json:"allow_raw_deflate,omitempty"`
}

// YAMLLimits bound a YAML document, when YAML is allowed at all.
type YAMLLimits struct {
	MaxBytes   int `json:"max_bytes,omitempty"`   // default 32768
	MaxDepth   int `json:"max_depth,omitempty"`   // default 32
	MaxNodes   int `json:"max_nodes,omitempty"`   // default 10000
	MaxAnchors int `json:"max_anchors,omitempty"` // anchors (&name) defined (default 4)
	MaxAliases int `json:"max_aliases,omitempty"` // aliases (*name) used (default 8)
}

// FormLimits bound URL-encoded parameters in a body or URL query, independently for each channel.
type FormLimits struct {
	MaxParams       int `json:"max_params,omitempty"`        // default 1000
	MaxNameLen      int `json:"max_name_len,omitempty"`      // bytes in a decoded name (default 256)
	MaxValueLen     int `json:"max_value_len,omitempty"`     // bytes in a decoded value (default 65536)
	MaxBracketDepth int `json:"max_bracket_depth,omitempty"` // a[b][c] is depth 2 (default 8)
}

// MultipartLimits bound a multipart body. It checks structure only: the proxy checks what an uploaded file is called and holds.
type MultipartLimits struct {
	MaxParts       int `json:"max_parts,omitempty"`        // default 100
	MaxHeaderBytes int `json:"max_header_bytes,omitempty"` // bytes in one part's header block (default 8192)
	MaxHeaders     int `json:"max_headers,omitempty"`      // header lines in one part (default 16)
	MaxBoundaryLen int `json:"max_boundary_len,omitempty"` // RFC 2046 allows 70 (default 70)
	MaxNameLen     int `json:"max_name_len,omitempty"`     // bytes in a part name (default 256)
}

// DefaultPolicy returns the policy a site gets when it names nothing, with every default written out.
func DefaultPolicy() Policy {
	return Policy{}.withDefaults()
}

func defaultAllowedTypes() []string {
	return []string{
		"application/x-www-form-urlencoded", "multipart/form-data",
		"application/json", "*+json",
		"application/xml", "text/xml", "*+xml",
		"application/graphql",
		"application/x-ndjson", "application/jsonl",
		"text/plain",
	}
}

func defaultCharsets() []string { return []string{"utf-8", "us-ascii", "iso-8859-1", "windows-1252"} }

func def(v *int, d int) {
	if *v == 0 {
		*v = d
	}
}

// withDefaults returns a copy with every unset field filled in. Slices are copied, so the caller's policy is never shared.
func (p Policy) withDefaults() Policy {
	if len(p.AllowedTypes) == 0 {
		p.AllowedTypes = defaultAllowedTypes()
	} else {
		p.AllowedTypes = append([]string(nil), p.AllowedTypes...)
	}
	if len(p.AllowedCharsets) == 0 {
		p.AllowedCharsets = defaultCharsets()
	} else {
		p.AllowedCharsets = append([]string(nil), p.AllowedCharsets...)
	}
	p.AllowOpaque = append([]string(nil), p.AllowOpaque...)
	p.GraphQLPaths = append([]string(nil), p.GraphQLPaths...)
	if p.Rules != nil {
		m := make(map[string]Action, len(p.Rules))
		for k, v := range p.Rules {
			m[k] = v
		}
		p.Rules = m
	}
	def(&p.OpaqueMaxBytes, 64<<10)
	def(&p.MaxBodyBytes, 1<<20)
	def(&p.MaxQueryBytes, 64<<10)

	def(&p.JSON.MaxDepth, 64)
	def(&p.JSON.MaxNodes, 50000)
	def(&p.JSON.MaxKeys, 20000)
	def(&p.JSON.MaxKeyLen, 1024)
	def(&p.JSON.MaxStringLen, 256<<10)
	def(&p.JSON.MaxNumberLen, 64)

	def(&p.XML.MaxDepth, 32)
	def(&p.XML.MaxAttributes, 64)
	def(&p.XML.MaxElements, 50000)
	def(&p.XML.MaxNameLen, 256)
	def(&p.XML.MaxAttrValueLen, 64<<10)
	def(&p.XML.MaxTextLen, 256<<10)

	def(&p.GraphQL.MaxDepth, 12)
	def(&p.GraphQL.MaxFields, 500)
	def(&p.GraphQL.MaxAliases, 20)
	def(&p.GraphQL.MaxDirectives, 50)
	def(&p.GraphQL.MaxBatch, 10)
	def(&p.GraphQL.MaxOperations, 10)
	def(&p.GraphQL.MaxQueryBytes, 64<<10)
	def(&p.GraphQL.MaxRequestFields, 1000)
	def(&p.GraphQL.MaxRequestAliases, 40)
	def(&p.GraphQL.MaxRequestDirectives, 100)

	def(&p.NDJSON.MaxLines, 1000)

	def(&p.Encoding.MaxOutput, 1<<20)
	def(&p.Encoding.MaxRatio, 100)

	def(&p.YAML.MaxBytes, 32<<10)
	def(&p.YAML.MaxDepth, 32)
	def(&p.YAML.MaxNodes, 10000)
	def(&p.YAML.MaxAnchors, 4)
	def(&p.YAML.MaxAliases, 8)

	def(&p.Form.MaxParams, 1000)
	def(&p.Form.MaxNameLen, 256)
	def(&p.Form.MaxValueLen, 64<<10)
	def(&p.Form.MaxBracketDepth, 8)
	def(&p.Query.MaxParams, 1000)
	def(&p.Query.MaxNameLen, 256)
	def(&p.Query.MaxValueLen, 64<<10)
	def(&p.Query.MaxBracketDepth, 8)

	def(&p.Multipart.MaxParts, 100)
	def(&p.Multipart.MaxHeaderBytes, 8192)
	def(&p.Multipart.MaxHeaders, 16)
	def(&p.Multipart.MaxBoundaryLen, 70)
	def(&p.Multipart.MaxNameLen, 256)
	return p
}

// Ceilings: the largest value a limit may be given. They exist so that a typo (an extra zero) cannot switch a bound off in practice.
const (
	ceilBytes = 64 << 20
	ceilCount = 10_000_000
	ceilDepth = 1000
)

type bound struct {
	name string
	v    int
	max  int
}

// Validate reports why a policy cannot be used. It is strict: an unknown rule name, an action that is not block, monitor or off, a
// malformed media type, a negative or absurd limit are all errors, so a mistake in a policy is found when it is loaded and not when
// an attack gets through.
func (p Policy) Validate() error {
	var errs []error
	names := make([]string, 0, len(p.Rules))
	for n := range p.Rules {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r := ruleByName(n)
		if r == nil {
			errs = append(errs, fmt.Errorf("rules: %q is not a rule name", n))
			continue
		}
		a := p.Rules[n]
		if a != Block && a != Monitor && a != Off {
			errs = append(errs, fmt.Errorf("rules: %s is %q, not block, monitor or off", n, a))
			continue
		}
		if (r == rPolicyInvalid || r == rInternal) && a != Block {
			errs = append(errs, fmt.Errorf("rules: %s cannot be %s: a body that could not be checked is never let through (use monitor mode to record only)", n, a))
		}
	}
	for _, t := range p.AllowedTypes {
		if !validTypeEntry(t) {
			errs = append(errs, fmt.Errorf("allowed_types: %q is not type/subtype, type/* or *+suffix in lower case", t))
		}
	}
	for _, t := range p.AllowOpaque {
		if !validOpaqueEntry(t) {
			errs = append(errs, fmt.Errorf("allow_opaque: %q is not a lower case media type or a prefix ending in *", t))
		}
	}
	for _, c := range p.AllowedCharsets {
		if c == "" || c != strings.ToLower(c) || !isToken(c) {
			errs = append(errs, fmt.Errorf("allowed_charsets: %q is not a lower case charset name", c))
		}
	}
	for _, g := range p.GraphQLPaths {
		if !strings.HasPrefix(g, "/") || strings.ContainsAny(g, "?# \t\r\n") {
			errs = append(errs, fmt.Errorf("graphql_paths: %q is not a path", g))
		}
	}
	if len(p.AllowedTypes) > 64 || len(p.AllowOpaque) > 64 || len(p.AllowedCharsets) > 64 || len(p.GraphQLPaths) > 256 {
		errs = append(errs, errors.New("a list is longer than 64 entries (256 for graphql_paths)"))
	}
	for _, b := range []bound{
		{"opaque_max_bytes", p.OpaqueMaxBytes, ceilBytes}, {"max_body_bytes", p.MaxBodyBytes, ceilBytes},
		{"max_query_bytes", p.MaxQueryBytes, ceilBytes},
		{"json.max_depth", p.JSON.MaxDepth, ceilDepth}, {"json.max_nodes", p.JSON.MaxNodes, ceilCount}, {"json.max_keys", p.JSON.MaxKeys, ceilCount},
		{"json.max_key_len", p.JSON.MaxKeyLen, ceilBytes}, {"json.max_string_len", p.JSON.MaxStringLen, ceilBytes}, {"json.max_number_len", p.JSON.MaxNumberLen, 1000},
		{"xml.max_depth", p.XML.MaxDepth, ceilDepth}, {"xml.max_attributes", p.XML.MaxAttributes, 10000}, {"xml.max_elements", p.XML.MaxElements, ceilCount},
		{"xml.max_name_len", p.XML.MaxNameLen, 65536}, {"xml.max_attr_value_len", p.XML.MaxAttrValueLen, ceilBytes}, {"xml.max_text_len", p.XML.MaxTextLen, ceilBytes},
		{"graphql.max_depth", p.GraphQL.MaxDepth, ceilDepth}, {"graphql.max_fields", p.GraphQL.MaxFields, ceilCount}, {"graphql.max_aliases", p.GraphQL.MaxAliases, ceilCount},
		{"graphql.max_directives", p.GraphQL.MaxDirectives, ceilCount}, {"graphql.max_batch", p.GraphQL.MaxBatch, 10000}, {"graphql.max_operations", p.GraphQL.MaxOperations, 10000},
		{"graphql.max_query_bytes", p.GraphQL.MaxQueryBytes, ceilBytes},
		{"graphql.max_request_fields", p.GraphQL.MaxRequestFields, ceilCount},
		{"graphql.max_request_aliases", p.GraphQL.MaxRequestAliases, ceilCount},
		{"graphql.max_request_directives", p.GraphQL.MaxRequestDirectives, ceilCount},
		{"ndjson.max_lines", p.NDJSON.MaxLines, ceilCount},
		{"encoding.max_output", p.Encoding.MaxOutput, ceilBytes}, {"encoding.max_ratio", p.Encoding.MaxRatio, 100000},
		{"yaml.max_bytes", p.YAML.MaxBytes, ceilBytes}, {"yaml.max_depth", p.YAML.MaxDepth, ceilDepth}, {"yaml.max_nodes", p.YAML.MaxNodes, ceilCount},
		{"yaml.max_anchors", p.YAML.MaxAnchors, 10000}, {"yaml.max_aliases", p.YAML.MaxAliases, 10000},
		{"form.max_params", p.Form.MaxParams, ceilCount}, {"form.max_name_len", p.Form.MaxNameLen, 65536}, {"form.max_value_len", p.Form.MaxValueLen, ceilBytes},
		{"form.max_bracket_depth", p.Form.MaxBracketDepth, 1000},
		{"query.max_params", p.Query.MaxParams, ceilCount}, {"query.max_name_len", p.Query.MaxNameLen, 65536}, {"query.max_value_len", p.Query.MaxValueLen, ceilBytes},
		{"query.max_bracket_depth", p.Query.MaxBracketDepth, 1000},
		{"multipart.max_parts", p.Multipart.MaxParts, 100000}, {"multipart.max_header_bytes", p.Multipart.MaxHeaderBytes, 1 << 20}, {"multipart.max_headers", p.Multipart.MaxHeaders, 1000},
		{"multipart.max_boundary_len", p.Multipart.MaxBoundaryLen, 200}, {"multipart.max_name_len", p.Multipart.MaxNameLen, 65536},
	} {
		if b.v < 0 {
			errs = append(errs, fmt.Errorf("%s is negative", b.name))
		} else if b.v > b.max {
			errs = append(errs, fmt.Errorf("%s is %d, above the ceiling %d", b.name, b.v, b.max))
		}
	}
	return errors.Join(errs...)
}

// ParsePolicy reads one JSON object up to MaxPolicyBytes. Field names must match their JSON tags exactly; duplicate members,
// null values, invalid UTF-8, unknown fields, trailing data and anything Validate refuses are errors. This reads configuration,
// not request bodies. Omit a field (or set a numeric limit to zero) to use its default.
func ParsePolicy(data []byte) (Policy, error) {
	if len(data) > MaxPolicyBytes {
		return Policy{}, errors.New("formats policy: exceeds 1 MiB")
	}
	if !utf8.Valid(data) {
		return Policy{}, errors.New("formats policy: invalid UTF-8")
	}
	check := json.NewDecoder(bytes.NewReader(data))
	check.UseNumber()
	if err := checkPolicyValue(check, reflect.TypeOf(Policy{})); err != nil {
		return Policy{}, fmt.Errorf("formats policy: %w", err)
	}
	if _, err := check.Token(); err != io.EOF {
		return Policy{}, errors.New("formats policy: data after the policy")
	}
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("formats policy: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Policy{}, errors.New("formats policy: data after the policy")
	}
	if err := p.Validate(); err != nil {
		return Policy{}, fmt.Errorf("formats policy: %w", err)
	}
	return p, nil
}

// The schema follows Policy's Go types, so nesting is bounded by that acyclic schema, not by input-controlled recursion.
// Reflection is only used when loading configuration; the request path does not use it.
func checkPolicyValue(dec *json.Decoder, typ reflect.Type) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return errors.New("null is not a policy value; omit the field to use its default")
	}
	switch typ.Kind() {
	case reflect.Struct, reflect.Map:
		if tok != json.Delim('{') {
			return errors.New("expected an object")
		}
		fields := make(map[string]reflect.Type)
		if typ.Kind() == reflect.Struct {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
				if name != "" && name != "-" && field.IsExported() {
					fields[name] = field.Type
				}
			}
		}
		seen := make(map[string]bool)
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("expected an object member name")
			}
			if seen[name] {
				return fmt.Errorf("duplicate member %q", name)
			}
			seen[name] = true
			valueType := fields[name]
			if typ.Kind() == reflect.Map {
				valueType = typ.Elem()
			}
			if valueType == nil {
				return fmt.Errorf("unknown field %q", name)
			}
			if err := checkPolicyValue(dec, valueType); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("expected end of object")
		}
	case reflect.Slice:
		if tok != json.Delim('[') {
			return errors.New("expected an array")
		}
		for dec.More() {
			if err := checkPolicyValue(dec, typ.Elem()); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("expected end of array")
		}
	case reflect.Bool:
		if _, ok := tok.(bool); !ok {
			return errors.New("expected a boolean")
		}
	case reflect.Int:
		if _, ok := tok.(json.Number); !ok {
			return errors.New("expected an integer")
		}
	case reflect.String:
		if _, ok := tok.(string); !ok {
			return errors.New("expected a string")
		}
	default:
		return errors.New("unsupported policy schema type")
	}
	return nil
}

func validTypeEntry(t string) bool {
	if t != strings.ToLower(t) {
		return false
	}
	if strings.HasPrefix(t, "*+") {
		return isToken(t[2:])
	}
	typ, sub, ok := strings.Cut(t, "/")
	if !ok || !isToken(typ) || typ == "*" {
		return false // "*/*" would be a list that allows nothing it names: allow the types a site receives, by name
	}
	return sub == "*" || isToken(sub)
}

func validOpaqueEntry(t string) bool {
	if t != strings.ToLower(t) {
		return false
	}
	t = strings.TrimSuffix(t, "*")
	typ, sub, ok := strings.Cut(t, "/")
	return ok && isToken(typ) && (sub == "" || isToken(sub))
}
