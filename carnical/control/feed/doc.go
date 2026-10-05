// SPDX-License-Identifier: Apache-2.0

// Package feed serves the signed pull feed (version 1) that the owner console already reads from every protected
// site, so a hosted Carnical looks to the owner's console and to the monthly reports exactly like one more site
// running the PHP firewall.
//
// The contract is the one in docs/backend-compat.md section 1, taken from the PHP answer (PortalFeed.php), the plan
// ("The feed, exactly (version 1)") and the Python reader (brief/waf/feed.py):
//
//	GET <path>/feed?since=<cursor>&days=<n>
//	Authorization: SFW1 key=<16 hex>, ts=<unix>, nonce=<32 hex>, sig=<64 hex>
//
// where sig is the lower-case hex of HMAC-SHA256 under the key's 32-byte secret over
// "SFW1\nGET\n" + the request target exactly as sent + "\n" + ts + "\n" + nonce.
//
// A Handler answers for one site. The site is fixed when the handler is made, never chosen by anything in the request,
// and a key belongs to exactly one site, so a key for one site cannot read another's feed even if both handlers share
// a key store. The data comes from an EventSource, which the owner connects to the real stores; every value it returns
// is checked against the reader's own limits and is cut or left out before it is sent, because the reader refuses a
// whole answer for a wrong frame and drops a whole event for one wrong field.
//
// Nothing in an answer is trusted text: events, paths and agent strings all came from visitors. The handler clips them
// to the reader's lengths, and when a key's addresses are "cut" it shortens every address it can find in the address
// fields and in the free-text fields that carry our own explanations.
package feed
