# Security Policy

## Scope

`ed25519` is a pure-Racket Ed25519 signature implementation (RFC 8032).
It signs and verifies; it does not encrypt and does not perform key
agreement.

## Reporting a vulnerability

Report privately via GitHub security advisories for this repository
(Security → Report a vulnerability). Do not open a public issue for an
unreleased vulnerability. You will get a response within a few days;
fixes land on `main` and are released as a patch version.

## Trust model and limitations

- **Not constant time.** Racket bignum arithmetic leaks timing and cache
  information. This implementation makes no side-channel resistance
  claim. Verification of public data is safe in any environment.
  Sign with this package only where attackers cannot measure signing
  time of high-value keys; production issuers should prefer a native
  provider (OpenSSL 3, libsodium, Nettle) and treat this package as the
  fallback of last resort.
- **No third-party audit.** The implementation follows RFC 8032 and the
  public-domain ref10 decompression technique. It is validated against
  all RFC 8032 section 7.1 test vectors and cross-checked
  byte-for-byte against OpenSSL 3 (see `NOTICE`), but it has not
  undergone an independent cryptographic audit.
- **Cofactorless verification.** Non-canonical encodings, non-canonical
  scalars (`S >= L`), and small-order public keys are rejected, aligning
  with OpenSSL 3 behavior.
- **Randomness.** `generate-keypair` uses the operating system entropy
  source via `racket/random`. Keys are only as strong as the host OS.
- **No memory locking.** Secret seeds are ordinary Racket byte strings;
  copies may persist in the GC heap. Keep secrets out of logs, stack
  traces, and printed structures.

## Supported versions

Only the latest released version receives security fixes.
