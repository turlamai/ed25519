#lang racket/base

;; Pure-Racket Ed25519 signatures (RFC 8032), with no FFI and no native
;; dependency. This package is a fallback for environments without a
;; cryptographic provider such as OpenSSL 3, libsodium or Nettle; native
;; providers remain preferable for production key holders. The
;; implementation is not constant time; see the README for the security
;; model and usage guidance.

(require racket/random
         "private/sha512.rkt"
         "private/group.rkt"
         "private/encode.rkt")

(provide (struct-out ed25519-keypair)
         generate-keypair
         keypair-public
         keypair-secret
         secret->public
         sign
         verify
         public-key-length
         secret-key-length
         signature-length)

(define public-key-length 32)
(define secret-key-length 32)
(define signature-length 64)

(struct ed25519-keypair (public secret) #:transparent)

;; --- argument checking -------------------------------------------------

;; Contract violations raise exn:fail:contract with descriptive messages.
(define (check-seed who v)
  (unless (and (bytes? v) (= secret-key-length (bytes-length v)))
    (raise-argument-error who "32-byte secret seed (bytes)" v))
  v)

(define (check-public who v)
  (unless (and (bytes? v) (= public-key-length (bytes-length v)))
    (raise-argument-error who "32-byte public key (bytes)" v))
  v)

(define (check-signature who v)
  (unless (and (bytes? v) (= signature-length (bytes-length v)))
    (raise-argument-error who "64-byte signature (bytes)" v))
  v)

;; --- secret expansion (RFC 8032 section 5.1.5) -------------------------

;; Clamp h[0..31]: clear the three lowest bits, clear the highest bit, set
;; the second-highest bit.
(define (clamped-scalar h0)
  (define b (bytes-copy h0))
  (bytes-set! b 0 (bitwise-and (bytes-ref b 0) #xF8))
  (bytes-set! b 31 (bitwise-ior (bitwise-and (bytes-ref b 31) #x7F) #x40))
  (bytes->scalar b))

;; SHA-512 of the seed splits into the clamped signing scalar and the
;; prefix that gets hashed together with each message.
(define (expand-secret seed)
  (define h (sha512 seed))
  (values (clamped-scalar (subbytes h 0 32)) (subbytes h 32 64)))

;; --- public API ---------------------------------------------------------

;; 32 bytes of OS entropy as the secret seed, via racket/random. No PRNG
;; seeding and no deterministic generation.
(define (generate-keypair)
  (define secret (crypto-random-bytes secret-key-length))
  (ed25519-keypair (secret->public secret) secret))

(define (keypair-public kp) (ed25519-keypair-public kp))
(define (keypair-secret kp) (ed25519-keypair-secret kp))

;; Derive the 32-byte public key of an existing seed.
(define (secret->public secret)
  (check-seed 'secret->public secret)
  (define-values (a _) (expand-secret secret))
  (point->bytes (pt-scalar-mult a base-point)))

;; Deterministic Ed25519 signature: the same message and seed always
;; produce the same 64 bytes (RFC 8032; Ed25519 has no nonce).
(define (sign message secret)
  (unless (bytes? message)
    (raise-argument-error 'sign "bytes?" message))
  (check-seed 'sign secret)
  (define-values (a prefix) (expand-secret secret))
  (define public (point->bytes (pt-scalar-mult a base-point)))
  (define r (modulo (bytes->scalar (sha512 (bytes-append prefix message))) L))
  (define r-encoding (point->bytes (pt-scalar-mult r base-point)))
  (define k (bytes->scalar (sha512 (bytes-append r-encoding public message))))
  (define s (modulo (+ r (* k a)) L))
  (bytes-append r-encoding (scalar->bytes s)))

;; Cofactorless verification: check [S]B == R + [k]A in the full group.
;;
;; Contract violations (non-bytes arguments, wrong lengths) raise
;; exn:fail:contract. Cryptographic failures return #f and never raise:
;; tampered signatures, wrong keys, non-canonical encodings (y >= p,
;; non-canonical sign, points off the curve), signatures with S >= L, and
;; small-order public keys are all rejected. Any unexpected internal
;; failure also yields #f (fail closed).
(define (verify message signature public)
  (unless (bytes? message)
    (raise-argument-error 'verify "bytes?" message))
  (check-signature 'verify signature)
  (check-public 'verify public)
  (with-handlers ([exn:fail? (lambda (_) #f)])
    (define r-encoding (subbytes signature 0 32))
    (define s (bytes->scalar (subbytes signature 32 64)))
    (and (< s L)                      ; reject malleable S = S + t*L
         (let ([r (bytes->point r-encoding)]
               [a (bytes->point public)])
           (and r
                a
                (not (small-order? a)) ; reject small-order public keys
                (let* ([k (bytes->scalar
                           (sha512 (bytes-append r-encoding public message)))]
                       [lhs (pt-scalar-mult s base-point)]
                       [rhs (pt-add r (pt-scalar-mult k a))])
                  (pt=? lhs rhs)))))))
