// SPDX-License-Identifier: Apache-2.0

// Package control is the API through which the customer web UI changes a tenant's Carnical settings, and a Go client
// for it. It is built to stay safe when the UI host is attacked, when the network is hostile, and when a request is
// replayed or altered on its way.
//
// An HTTP request is accepted only if every layer agrees:
//
//  1. Transport. TLS 1.3 only, a client certificate that chains to the configured CA (TLSConfig), reloaded from disk
//     without a restart. No session tickets, so every connection proves its certificate again.
//  2. Credential. Each UI deployment has a service credential: the SHA-256 fingerprints of the public keys of the
//     client certificates it may use, an Ed25519 public key it signs requests with, the tenants and scopes it may use,
//     an optional list of source addresses, an expiry and a revoked flag. A request needs both a certificate whose
//     fingerprint is the credential's and a valid signature (protocol.go), so a stolen certificate, or a proxy that
//     terminates TLS, is not enough.
//  3. Authorisation. The tenant in the path must be one the credential may act for, the credential must hold the scope
//     the route needs, and a change that weakens a tenant's protection needs a recent step-up (the customer typed the
//     password again, asserted by the UI inside the signed request).
//  4. The endpoints (routes.go), each validated before it touches a store.
//  5. The HTTP layer: documented methods only, strict content type, bounded body, header and in-flight limits, no CORS,
//     uniform errors that never echo input, panic recovery.
//  6. An audit log (audit.go) of every authenticated action and every authentication failure, hash-chained so that a
//     deleted or edited line can be found.
//
// Everything the API stores or does is behind small interfaces defined in ports.go (the policy store, the validator,
// the publisher, the event source, the hostname registry and verifier). The owner connects the real ones.
//
// What is secret here: the UI's Ed25519 private key and TLS private key, and the server's TLS private key. Nothing in
// this package logs, returns or stores any of them, and no error text carries request content.
package control
