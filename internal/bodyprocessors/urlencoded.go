// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"io"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
	urlutil "github.com/corazawaf/coraza/v3/internal/url"
)

type urlencodedBodyProcessor struct {
}

func (*urlencodedBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, reader); err != nil {
		return err
	}

	b := buf.String()
	// ParseQuery itself stops once options.ArgumentLimit total pairs have
	// been parsed (see GHSA-3ww9-vw83-9w5x): the copy below never needs to
	// re-enforce the cap, since values can never hold more than the limit.
	// ARGS_POST matches keys case-insensitively by default, so two keys that
	// differ only in case share one entry. Add each pair in the order it was
	// sent, as the JSON and multipart processors already do, so every value is
	// kept instead of a later write for a folded key replacing the earlier one.
	pairs, truncated := urlutil.ParseQueryOrdered(b, '&', options.ArgumentLimit)
	argsCol := v.ArgsPost()
	for _, kv := range pairs {
		argsCol.Add(kv.Key, kv.Value)
	}
	if truncated {
		v.ArgumentsLimitReached().(*collections.Single).Set("1")
	}
	v.RequestBody().(*collections.Single).Set(b)
	v.RequestBodyLength().(*collections.Single).Set(strconv.Itoa(len(b)))
	return nil
}

func (*urlencodedBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	return nil
}

var (
	_ plugintypes.BodyProcessor = &urlencodedBodyProcessor{}
)

func init() {
	RegisterBodyProcessor("urlencoded", func() plugintypes.BodyProcessor {
		return &urlencodedBodyProcessor{}
	})
}
