#lang scribble/manual

@(require scribble/example
          (for-label racket/base racket/random ed25519))

@(define ed25519-eval (make-base-eval))
@(ed25519-eval '(require ed25519 racket/random))

@title[#:tag "ed25519"]{ed25519: Pure-Racket Ed25519 Signatures}

@defmodule[ed25519]

This package implements Ed25519 signatures exactly as specified in
@hyperlink["https://www.rfc-editor.org/rfc/rfc8032" "RFC 8032"] using only
pure Racket: no FFI, no shared libraries, no external tools. It exists as
the last-resort fallback of a provider chain: if no native provider (such
as OpenSSL 3 via @racket[crypto-lib], libsodium, or Nettle) is available,
Ed25519 signing and verification still work in any Racket environment.

@itemlist[
  @item{Signatures are @emph{deterministic}: the same message and secret
    seed always produce the same 64-byte signature.}
  @item{The implementation matches RFC 8032 and is validated against all
    RFC 8032 section 7.1 test vectors plus byte-for-byte cross-validation
    against OpenSSL 3.}
  @item{It is @emph{not} constant time. Verification of public data is
    safe anywhere; production @emph{key holders} should prefer a native
    provider (see @secref["ed25519-security"]).}
]

@section[#:tag "ed25519-example"]{Quick Start}

@examples[#:eval ed25519-eval #:label ""]{
  (require ed25519)

  (define kp (generate-keypair))
  (define message #"update manifest 2026-11-04")
  (define sig (sign message (keypair-secret kp)))
  (verify message sig (keypair-public kp))
}

A key pair carries the public key and the secret seed, both as 32-byte
byte strings. The secret seed is the RFC 8032 seed: 32 bytes of entropy,
not the 64-byte expanded form.

@examples[#:eval ed25519-eval #:label ""]{
  (require ed25519)

  (define seed (crypto-random-bytes 32))   ; caller-provided seed
  (secret->public seed)                    ; derive the public key
}

@section[#:tag "ed25519-keys"]{Keys}

@defstruct*[ed25519-keypair ([public bytes?] [secret bytes?])]{
  A public/secret key pair. @racket[public] is exactly 32 bytes; the
  @racket[secret] field is the 32-byte RFC 8032 seed. The structure is
  transparent: treat the @racket[secret] field with the same care as any
  private key material.
}

@defproc[(generate-keypair) ed25519-keypair?]{
  Generates a fresh key pair from 32 bytes of OS entropy
  (@racket[crypto-random-bytes]); no deterministic or time-based
  generation is involved.
}

@defproc[(keypair-public [kp ed25519-keypair?]) bytes?]{
  Returns the 32-byte public key of @racket[kp].
}

@defproc[(keypair-secret [kp ed25519-keypair?]) bytes?]{
  Returns the 32-byte secret seed of @racket[kp].
}

@defproc[(secret->public [secret bytes?]) bytes?]{
  Derives the 32-byte public key for the 32-byte secret seed
  @racket[secret]. Use this when a seed already exists (for example,
  persisted key material). Raises @racket[exn:fail:contract] unless
  @racket[secret] is a byte string of exactly 32 bytes.
}

@section[#:tag "ed25519-sign"]{Signing and Verification}

@defproc[(sign [message bytes?] [secret bytes?]) bytes?]{
  Signs @racket[message] with the 32-byte secret seed @racket[secret] and
  returns the 64-byte signature. Deterministic: identical inputs yield
  identical signatures. Keys and messages are raw bytes only; callers
  encode strings themselves (UTF-8 is the recommended encoding). Raises
  @racket[exn:fail:contract] for non-byte or wrong-length arguments.
}

@defproc[(verify [message bytes?] [signature bytes?] [public bytes?]) boolean?]{
  Verifies @racket[signature] over @racket[message] against the 32-byte
  public key @racket[public], returning @racket[#t] or @racket[#f].

  All cryptographic failures return @racket[#f] and never raise: tampered
  messages or signatures, wrong keys, non-canonical point encodings,
  non-canonical scalars (@racket[S] at or above the group order), and
  small-order public keys are all rejected. Length or type violations
  raise @racket[exn:fail:contract].
}

@section[#:tag "ed25519-constants"]{Constants}

@defthing[public-key-length 32]{
  Length in bytes of a public key.
}

@defthing[secret-key-length 32]{
  Length in bytes of a secret seed.
}

@defthing[signature-length 64]{
  Length in bytes of a signature.
}

@section[#:tag "ed25519-security"]{Security Considerations}

@itemlist[
  @item{@bold{Not constant time.} Racket bignum arithmetic leaks timing
    information. Verification of public data (update manifests, license
    proofs, signed attestations) is the intended use. Production
    @emph{issuers} should sign with a native provider and use this
    implementation only as a fallback in controlled environments.}
  @item{@bold{No third-party audit.} The implementation follows RFC 8032
    and ref10's decompression technique, is validated against all RFC 8032
    vectors, and is cross-checked byte-for-byte against OpenSSL 3, but it
    has not undergone an independent cryptographic audit.}
  @item{@bold{This package signs, it does not encrypt.} Ed25519 is a
    signature scheme; it provides no confidentiality and no key
    agreement.}
  @item{@bold{Secrets are ordinary byte strings.} Transparent structures
    can print secret seeds; keep them out of logs and error messages.}
]

@bold{Provenance.} The algorithm follows RFC 8032 section 5.1 directly,
with the decompression technique from the public-domain ref10 reference
implementation (D. J. Bernstein et al.) and SHA-512 per FIPS 180-4.
See the package NOTICE file for full attribution.
