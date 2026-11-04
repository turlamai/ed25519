# ed25519

Pure-Racket Ed25519 signatures — no FFI, no native libraries, no external
tools.

[中文文档](README.zh-CN.md)

`ed25519` implements Ed25519 exactly as specified in
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) using only pure Racket
bignum arithmetic. Signatures are byte-for-byte interoperable with OpenSSL 3,
libsodium, and every other Ed25519 implementation.

## Install

```sh
raco pkg install ed25519
```

## Example

```racket
(require ed25519)

(define kp (generate-keypair))
(define message #"update manifest 2026-11-04")

(define sig (sign message (keypair-secret kp)))
(verify message sig (keypair-public kp)) ; => #t
(verify #"tampered" sig (keypair-public kp)) ; => #f
```

Existing 32-byte seeds work too:

```racket
(secret->public seed)          ; derive the public key
(sign message seed)            ; sign with an existing seed
```

## Where it fits

This package is the **last-resort fallback** of an Ed25519 provider chain,
not a replacement for native cryptography:

1. OpenSSL 3 via `crypto-lib` — preferred everywhere it is available;
2. libsodium — preferred where packaged;
3. Nettle — preferred where its Ed25519 backend exists;
4. `ed25519` (this package) — guarantees that *any* Racket environment can
   sign and verify without native dependencies.

Verification of public data (update manifests, license proofs, signed
attestations) is safe to do with this package everywhere. Production
*issuers* holding private keys should prefer a native provider; if they
must use this package, see the security note below.

## API

| Binding | Contract |
|---|---|
| `generate-keypair` | `-> ed25519-keypair?` |
| `keypair-public kp` | `-> 32 bytes` |
| `keypair-secret kp` | `-> 32 bytes` (RFC 8032 seed) |
| `secret->public secret` | `32 bytes -> 32 bytes` |
| `sign message secret` | `bytes? 32 bytes -> 64 bytes`, deterministic |
| `verify message signature public` | `bytes? 64 bytes 32 bytes -> boolean?` |
| `public-key-length` / `secret-key-length` / `signature-length` | `32` / `32` / `64` |

`verify` never raises on untrusted input: tampered messages or signatures,
wrong keys, non-canonical encodings (`y >= p`, non-canonical sign, points
off the curve), non-canonical scalars (`S >= L`), and small-order public
keys all return `#f`. Wrong argument types or lengths raise
`exn:fail:contract`. Verification is cofactorless, matching OpenSSL 3.

## Security

- **Not constant time.** Racket bignum arithmetic leaks timing
  information. Do not use this package where attackers can measure
  signing times of high-value keys.
- **No third-party audit.** The implementation follows RFC 8032 and the
  public-domain ref10 decompression technique, is validated against all
  RFC 8032 section 7.1 test vectors, and is cross-checked byte-for-byte
  against OpenSSL 3 — but it has not undergone an independent
  cryptographic audit.
- **Signatures only.** Ed25519 provides no encryption and no key
  agreement.
- `generate-keypair` uses the OS entropy source (`racket/random`'s
  `crypto-random-bytes`); no PRNG seeding is involved.

## Performance

Measured with Racket 9.3 CS (Racket CS bignums, no JIT tuning), Apple
Silicon:

| Message | Sign | Verify |
|---|---|---|
| empty | ~3.9 ms | ~5.4 ms |
| 32 B | ~3.6 ms | ~4.9 ms |
| 1 KB | ~5.1 ms | ~6.5 ms |
| 4 KB | ~9.3 ms | ~7.8 ms |

Correctness first, speed second: this is far slower than native providers
and acceptable for license and update verification. The brief's CI budget
(sign < 500 ms, verify < 250 ms) is met with a wide margin.

## Compatibility

- All RFC 8032 §7.1 test vectors pass byte-for-byte (public keys,
  signatures, verification).
- 1000+ randomized cross-validation cases against OpenSSL 3 (`pkeyutl
  -rawin`): Racket-signed messages verify under OpenSSL, OpenSSL-signed
  messages verify under Racket, and signatures are byte-identical.
- Negative matrix: every single-bit message flip, every single-bit
  signature flip (all 512 bits), `S + L` malleability, non-canonical
  encodings, and small-order public keys are rejected.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for algorithm
provenance (RFC 8032; ref10 decompression technique, public domain).
