# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1] - 2026-11-04

### Added

- Pure-Racket Ed25519 signatures (RFC 8032): `generate-keypair`,
  `secret->public`, `sign`, `verify`, `keypair-public`, `keypair-secret`
  and the `ed25519-keypair` transparent structure. No FFI and no native
  dependency; the shipped collection depends on `base` alone.
- Cofactorless verification aligned with OpenSSL 3: non-canonical
  encodings, `S >= L` scalars, and small-order public keys are rejected;
  `verify` never raises on untrusted bytes.
- All RFC 8032 §7.1 test vectors pass byte-for-byte; 1000+-case
  randomized cross-validation against OpenSSL 3 with byte-identical
  signatures; negative, property, and fuzz test suites.
- Scribble documentation with executable examples.

[Unreleased]: https://github.com/turlamai/ed25519/compare/v0.1...HEAD
[0.1]: https://github.com/turlamai/ed25519/releases/tag/v0.1
