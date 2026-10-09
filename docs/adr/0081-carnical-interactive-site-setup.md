# ADR-0081: Carnical interactive site setup

- **Status:** proposed
- **Date:** 2026-10-09 (expected; update before merge)
- **Version:** unreleased (post-v3.8.1)
- **PR:** No PR opened (owner-authorized Carnical development)
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Putting an installed proxy in front of a website currently requires assembling CLI flags or
editing a JSON example. Operators need a short setup command that checks inputs, asks before
writing and protects private infrastructure settings without unattended password prompts.

## Decision Drivers

- Use the existing startup checks and strict flag types on Windows and Linux.
- Keep explicit consent, bounded input, no overwrite and no plaintext staging files.
- Preserve ordinary site files and readable protection settings.
- Protect encryption keys with real platform permissions without CGO or new unsafe code.

## Considered Options

- A passphrase-encrypted file would need a password input or another stored secret at service startup.
- Putting an encryption key in the site file would not protect a copied configuration.
- A separate random key with platform file protection supports unattended startup and separate backups.

## Decision Outcome

Add `carnical setup`, using an independent FlagSet to run the actual deployment checks without
listening. Save public settings in the existing version-1 flags object and private origin
details/credential paths in an optional authenticated AES-256-GCM section. Go's random-nonce
AEAD owns nonce generation. A separate 32-byte key is identified by a restricted random ID,
loaded from the current account's key store or the CLI-only `-config-key-file` path.

The loader authenticates once at startup, rejects duplicate flags across both sections and
applies the existing explicit CLI precedence. Bootstrap/action flags cannot appear in either
section. Unix keys are owner-only; Windows files receive protected current-user/SYSTEM ACLs
before data is written. Windows ACL changes use an identity-checked handle. File creation is
exclusive and bounded. Credential files themselves remain external and need their own protection.

Public settings remain trusted operator policy, with no claim of cryptographic authentication.
The key is accessible to the WAF identity and administrators. Service-account transfer requires
explicit permissions and validation under that identity. Setup neither issues certificates nor
changes DNS, network access or services. Existing plaintext site configurations remain supported.

## Technical Discussion

No substantive technical discussion recorded; this record accompanies the owner-authorized change.

## References

- ADR-0078: Authenticated Carnical origin connections
- ADR-0079: Carnical availability and portable runtime
- [Setup guide](../../carnical/docs/setup.md)
- [Go random-nonce AEAD](https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce)
- [Windows security descriptor strings](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
