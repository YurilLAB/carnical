module github.com/corazawaf/coraza/v3

go 1.27.0

// Testing dependencies:
// - go-mockdns
// - go-modsecurity (optional)

// Development dependencies:
// - mage

// Build dependencies:
// - libinjection-go
// - aho-corasick
// - gjson
// - binaryregexp
// - ocsf-schema-golang

require (
	github.com/corazawaf/coraza-coreruleset v0.0.0-20240226094324-415b1017abdc
	github.com/corazawaf/libinjection-go v0.3.3
	github.com/foxcpp/go-mockdns v1.3.0
	github.com/jcchavezs/mergefs v0.1.1
	github.com/kaptinlin/jsonschema v0.9.10
	github.com/magefile/mage v1.17.2
	github.com/mccutchen/go-httpbin/v2 v2.25.0
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20250424160509-463d218d4745
	github.com/tidwall/gjson v1.20.0
	github.com/valllabh/ocsf-schema-golang v1.0.3
	golang.org/x/net v0.60.0
	golang.org/x/sync v0.23.0
	rsc.io/binaryregexp v0.2.0
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/kaptinlin/jsonpointer v0.4.28 // indirect
	github.com/miekg/dns v1.1.68 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

retract v3.2.2
