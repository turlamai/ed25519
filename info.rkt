#lang info

(define name "ed25519")
(define collection 'multi)
(define version "0.1")
(define pkg-desc
  "Pure-Racket Ed25519 signatures, validated against RFC 8032 and OpenSSL 3")
(define pkg-authors '(turlamai))
(define license 'Apache-2.0)

;; Tests ship inside this package (ed25519-test/), so their requirements
;; are runtime deps — raco setup --check-pkg-deps classifies ed25519-test
;; requires as run-mode (glaze/foreman precedent).
;; net-lib is test-only in practice: the cross-check builds RFC 8410 PEM
;; keys via net/base64. The shipped ed25519 collection itself depends on
;; base alone.
(define deps '(["base" #:version "9.0"] "rackunit-lib" "net-lib"))
(define build-deps '("racket-doc" "scribble-lib"))
