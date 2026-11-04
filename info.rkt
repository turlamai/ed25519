#lang info

(define name "ed25519")
(define collection 'multi)
(define version "0.1")
(define pkg-desc
  "Pure-Racket Ed25519 signatures, validated against RFC 8032 and OpenSSL 3")
(define pkg-authors '(turlamai))
(define license 'Apache-2.0)

(define deps '(["base" #:version "9.0"]))
;; net-lib is test-only: the cross-check builds RFC 8410 PEM keys via
;; net/base64. The shipped ed25519 collection depends on base alone.
(define build-deps '("rackunit-lib" "net-lib" "racket-doc" "scribble-lib"))
