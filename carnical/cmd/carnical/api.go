// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/YurilLAB/coraza/carnical/apiguard"
)

// Import locally, before opening the listener. No discovery, external references,
// learning, automatic promotion or network access is involved in this contract.
func configureAPI(path, mode, formatsMode string) (*apiguard.Guard, apiguard.Report, error) {
	var rep apiguard.Report
	if mode != "block" && mode != "monitor" {
		return nil, rep, errors.New("-api-spec-mode must be block or monitor")
	}
	if path == "" {
		return nil, rep, nil
	}
	if mode == "block" && formatsMode != "block" {
		return nil, rep, errors.New("-api-spec-mode block requires -formats-mode block for structural validation")
	}
	f, err := os.Open(path) // #nosec G304 -- Operator-selected API spec is read before listening; regular-file, size and schema checks follow.
	if err != nil {
		return nil, rep, fmt.Errorf("-api-spec: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, rep, errors.New("-api-spec must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, apiguard.MaxDocumentBytes+1))
	if err != nil {
		return nil, rep, fmt.Errorf("-api-spec: %w", err)
	}
	if len(data) > apiguard.MaxDocumentBytes {
		return nil, rep, errors.New("-api-spec exceeds 5 MiB")
	}
	model, rep, err := apiguard.ImportOpenAPI(data)
	if err != nil {
		return nil, rep, fmt.Errorf("-api-spec: %w", err)
	}
	if len(model.Routes) == 0 {
		return nil, rep, errors.New("-api-spec describes no routes")
	}
	if mode == "block" {
		if len(rep.Warnings) > 0 || rep.WarningsDropped > 0 {
			return nil, rep, errors.New("-api-spec contains unsupported or weakened constraints; review it in monitor mode and correct the import warnings before blocking")
		}
		for _, route := range model.Routes {
			if !route.NoBody && len(route.ContentTypes) == 0 {
				return nil, rep, errors.New("-api-spec block requires explicit JSON content types for an allowed request body")
			}
			if len(route.ContentTypes) > 1 {
				return nil, rep, errors.New("-api-spec block currently requires one request body media type per route; multiple schemas require an application validator")
			}
			for _, param := range route.Params {
				if param.Style == "deepObject" || param.Schema != nil && schemaHasObject(param.Schema, 0) {
					return nil, rep, errors.New("-api-spec block supports scalar and array parameters; object parameters require an application validator")
				}
			}
			if route.Body != nil && len(route.ContentTypes) == 0 {
				return nil, rep, errors.New("-api-spec block requires explicit JSON content types for a body schema")
			}
			for _, ct := range route.ContentTypes {
				if strings.Contains(ct, "*") || ct != "application/json" && !strings.HasSuffix(ct, "+json") {
					return nil, rep, errors.New("-api-spec block currently validates JSON body schemas; non-JSON body schemas require an application validator")
				}
			}
		}
	}
	choice := apiguard.ModeEnforce
	if mode == "monitor" {
		choice = apiguard.ModeMonitor
	}
	cfg := apiguard.Config{Mode: choice, RefuseUnknownParams: true,
		Modes: apiguard.Modes{Methods: apiguard.ModeOff, BodySize: apiguard.ModeOff, AuthRate: apiguard.ModeOff,
			Rate: apiguard.ModeOff, Format: choice, MassAssign: apiguard.ModeOff, Spec: choice, Learned: apiguard.ModeOff}}
	g, err := apiguard.New(cfg)
	if err == nil {
		err = g.SetModel(model)
	}
	if err != nil {
		return nil, rep, fmt.Errorf("-api-spec: %w", err)
	}
	return g, rep, nil
}

// Composition can hide an object parameter behind anyOf/allOf. Bound traversal
// and refuse references here; body references remain handled by the importer.
func schemaHasObject(s *apiguard.Schema, depth int) bool {
	if s == nil {
		return false
	}
	if depth > 32 || s.Ref != "" || s.Not != nil {
		return true
	}
	for _, typ := range s.Type {
		if typ == "object" {
			return true
		}
	}
	if len(s.Properties) > 0 || s.AdditionalSchema != nil || schemaHasObject(s.Items, depth+1) {
		return true
	}
	for _, group := range [][]*apiguard.Schema{s.OneOf, s.AnyOf, s.AllOf} {
		for _, child := range group {
			if schemaHasObject(child, depth+1) {
				return true
			}
		}
	}
	return false
}
