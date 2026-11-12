# Contributing

Thanks for considering a contribution.

## Ground rules

- **Correctness over everything.** This package implements Ed25519
  (RFC 8032). Do not "optimize" the algorithm in ways that change
  semantics; do not invent cryptographic shortcuts.
- **No new dependencies.** The shipped `ed25519` collection must depend
  on `base` alone — that is the reason this package exists. Test-only
  dependencies belong in `build-deps` and only in `ed25519-test/`.
- **Never skip or weaken a cryptographic test to make CI green.** If a
  test fails, the implementation is wrong or the test is wrong; say
  which and why.

## Workflow

1. `git pull --rebase` on `main`; keep the working tree clean.
2. For behavior changes, open an issue first so the change can be
   discussed before code lands.
3. Keep one logical change per pull request; keep `main` green.
4. Run the full gate locally before pushing:

   ```sh
   raco pkg install --auto --link --name ed25519 "$PWD"
   raco test -p ed25519
   raco setup --doc-index --check-pkg-deps --pkgs ed25519
   ```

   With an OpenSSL 3 CLI available (`ED25519_OPENSSL=/path/to/openssl`),
   the cross-check runs for real; on machines without one it skips and
   CI runs it on Ubuntu instead.

5. Public API changes update the Scribble documentation and both READMEs
   (English and Chinese) in the same pull request.
6. Add release notes to `CHANGELOG.md` (Keep a Changelog format) for
   anything user-visible.

## Tests

All test files live in the private `ed25519-test/` collection:

- `rfc8032.rkt` — every RFC 8032 §7.1 vector, byte-for-byte;
- `negative.rkt` — tampering, malleability, non-canonical encodings,
  small-order keys, contract violations;
- `property.rkt` — determinism and roundtrip properties;
- `fuzz.rkt` — `verify` never raises on untrusted bytes;
- `cross-check.rkt` — OpenSSL 3 interop (skips without OpenSSL 3).

`raco test -p ed25519` must pass on Racket 9.0 and 9.3 before any push
to `main`.

## License

By contributing you agree your contributions are licensed under the
Apache License, Version 2.0.
