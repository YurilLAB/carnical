package formats

import "strings"

// kind is how a body is read, decided from its media type.
type kind uint8

const (
	kindNone      kind = iota // no usable Content-Type: sniffed, not parsed
	kindOther                 // a type the site allows that has no parser here
	kindOpaque                // a binary type the site allows, with a size cap
	kindForm                  // application/x-www-form-urlencoded
	kindMultipart             // multipart/*
	kindJSON                  // application/json, *+json
	kindNDJSON                // application/x-ndjson, application/jsonl
	kindXML                   // application/xml, text/xml, *+xml
	kindGraphQL               // application/graphql
	kindYAML                  // application/yaml, text/yaml, application/x-yaml, *+yaml
	kindText                  // text/plain
)

func kindOf(m mediaType) kind {
	typ, sub := m.typ, m.sub
	full := typ + "/" + sub
	switch {
	case full == "application/x-www-form-urlencoded":
		return kindForm
	case typ == "multipart":
		return kindMultipart
	case full == "application/json", full == "text/json", full == "application/x-json", strings.HasSuffix(sub, "+json"):
		return kindJSON
	case full == "application/x-ndjson", full == "application/ndjson", full == "application/jsonl", full == "application/x-jsonlines",
		full == "application/jsonlines", full == "application/x-jsonl":
		return kindNDJSON
	case full == "application/xml", full == "text/xml", strings.HasSuffix(sub, "+xml"):
		return kindXML
	case full == "application/graphql":
		return kindGraphQL
	case full == "application/yaml", full == "text/yaml", full == "application/x-yaml", full == "text/x-yaml", strings.HasSuffix(sub, "+yaml"):
		return kindYAML
	case full == "text/plain":
		return kindText
	}
	return kindOther
}

// typeSet is the allowed media types: exact ones, "type/*" and "*+suffix".
type typeSet struct {
	exact  map[string]bool
	wild   map[string]bool
	suffix map[string]bool
}

func newTypeSet(entries []string) typeSet {
	s := typeSet{exact: map[string]bool{}, wild: map[string]bool{}, suffix: map[string]bool{}}
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e, "*+"):
			s.suffix[e[1:]] = true
		case strings.HasSuffix(e, "/*"):
			s.wild[strings.TrimSuffix(e, "/*")] = true
		default:
			s.exact[e] = true
		}
	}
	return s
}

func (s typeSet) has(typ, sub string) bool {
	if s.exact[typ+"/"+sub] || s.wild[typ] {
		return true
	}
	if i := strings.LastIndexByte(sub, '+'); i >= 0 && s.suffix[sub[i:]] {
		return true
	}
	return false
}

// The binary types nothing can inspect: whatever a client puts in them reaches the application as bytes no rule can read.
var opaqueExact = map[string]bool{
	"application/octet-stream": true,
	"application/msgpack":      true, "application/x-msgpack": true, "application/vnd.msgpack": true,
	"application/cbor": true, "application/cbor-seq": true,
	"application/protobuf": true, "application/x-protobuf": true, "application/vnd.google.protobuf": true,
	"application/x-thrift": true, "application/vnd.apache.thrift.binary": true,
	"application/avro": true, "application/vnd.apache.avro+binary": true,
	"application/bson": true, "application/x-bson": true,
	"application/x-amf":                    true,
	"application/x-java-serialized-object": true,
}

var opaquePrefix = []string{"application/grpc"}

var opaqueSuffix = []string{"+cbor", "+msgpack", "+protobuf", "+proto", "+bson"}

func (in *Inspector) isOpaque(m mediaType) bool {
	full := m.typ + "/" + m.sub
	if opaqueExact[full] {
		return true
	}
	for _, p := range opaquePrefix {
		if strings.HasPrefix(full, p) {
			return true
		}
	}
	for _, s := range opaqueSuffix {
		if strings.HasSuffix(m.sub, s) {
			return true
		}
	}
	return false
}

// opaqueSet is the opaque types a site said it receives: exact media types and prefixes ending in "*".
type opaqueSet struct {
	exact    map[string]bool
	prefixes []string
}

func newOpaqueSet(entries []string) opaqueSet {
	s := opaqueSet{exact: map[string]bool{}}
	for _, e := range entries {
		if strings.HasSuffix(e, "*") {
			s.prefixes = append(s.prefixes, strings.TrimSuffix(e, "*"))
		} else {
			s.exact[e] = true
		}
	}
	return s
}

func (s opaqueSet) has(full string) bool {
	if s.exact[full] {
		return true
	}
	for _, p := range s.prefixes {
		if strings.HasPrefix(full, p) {
			return true
		}
	}
	return false
}
