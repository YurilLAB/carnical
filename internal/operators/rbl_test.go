// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package operators

import (
	"context"
	"net"
	"testing"

	"github.com/foxcpp/go-mockdns"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type rblTestResolver struct{ mockdns.Resolver }

// net.Resolver treats a DNS answer with no TXT records as not found; mockdns's
// in-process resolver instead returns an empty successful result.
func (r *rblTestResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	txt, err := r.Resolver.LookupTXT(ctx, name)
	if err == nil && len(txt) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return txt, err
}

func TestRbl(t *testing.T) {
	opts := plugintypes.OperatorOptions{
		Arguments: "xbl.spamhaus.org",
	}
	op, err := newRBL(opts)
	if err != nil {
		t.Fatal("Cannot init rbl operator")
	}

	zones := map[string]mockdns.Zone{
		"valid_no_txt.xbl.spamhaus.org.": {
			A: []string{"1.2.3.4"},
		},
		"valid_txt.xbl.spamhaus.org.": {
			A:   []string{"1.2.3.5"},
			TXT: []string{"not blocked"},
		},
		"blocked.xbl.spamhaus.org.": {
			A:   []string{"1.2.3.6"},
			TXT: []string{"blocked"},
		},
	}
	// Exercise the operator's DNS results without requiring one port number to
	// be free for both TCP and UDP, or changing the process-wide default resolver.
	op.(*rbl).resolver = &rblTestResolver{mockdns.Resolver{Zones: zones}}

	t.Run("Valid hostname with no TXT record", func(t *testing.T) {
		if op.Evaluate(nil, "valid_no_txt") {
			t.Errorf("Unexpected result for valid hostname with no TXT record")
		}
	})

	t.Run("Valid hostname with TXT record", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		if !op.Evaluate(tx, "valid_txt") {
			t.Errorf("Unexpected result for valid hostname")
		}
		if want, have := "not blocked", tx.Variables().TX().Get("httpbl_msg")[0]; want != have {
			t.Errorf("Unexpected result for valid hostname: want %q, have %q", want, have)
		}
	})

	t.Run("Invalid hostname", func(t *testing.T) {
		if op.Evaluate(nil, "invalid") {
			t.Errorf("Unexpected result for invalid hostname")
		}
	})

	t.Run("Blocked hostname", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		if !op.Evaluate(tx, "blocked") {
			t.Fatal("Unexpected result for blocked hostname")
		}
		t.Log(tx.Variables().TX().Get("httpbl_msg"))
		if want, have := "blocked", tx.Variables().TX().Get("httpbl_msg")[0]; want != have {
			t.Errorf("Unexpected result for valid hostname: want %q, have %q", want, have)
		}
	})
}
