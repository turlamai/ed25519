#lang racket/base

;; Fuzz tests (release brief section 6.3, last item): verify must accept
;; or reject arbitrary untrusted bytes as a boolean and never raise, and
;; the sign pipeline must survive arbitrary seeds. Random signatures are
;; rejected outright (acceptance probability is negligible below 2^-200),
;; so any #t indicates a catastrophic bug.

(require rackunit
         racket/random
         ed25519)

;; Random 64-byte signatures against random and valid public keys: never
;; raise, and (with overwhelming probability) always reject.
(define iterations 1000)
(for ([i (in-range iterations)])
  (define sig (crypto-random-bytes 64))
  (define pub (crypto-random-bytes 32))
  (define msg (crypto-random-bytes (random 64)))
  (define result (verify msg sig pub))
  (check-true (boolean? result) (format "verify returned a boolean (~a)" i))
  (check-false result (format "random signature accepted (~a)" i)))

;; Random public keys against a genuinely valid signature: reject.
(define kp (generate-keypair))
(define sig (sign #"fuzz message" (keypair-secret kp)))
(for ([i (in-range 200)])
  (define pub (crypto-random-bytes 32))
  (define result (verify #"fuzz message" sig pub))
  (check-false result (format "valid signature accepted by random key (~a)" i)))

;; Arbitrary seeds flow through sign without raising and verify correctly.
(for ([i (in-range 100)])
  (define seed (crypto-random-bytes 32))
  (define msg (crypto-random-bytes (random 128)))
  (define pk (secret->public seed))
  (define result (verify msg (sign msg seed) pk))
  (check-true result (format "arbitrary-seed roundtrip (~a)" i)))

;; Truncated and oversized but structurally random inputs.
(for ([len (in-list '(0 1 31 33 63 65 128))])
  (check-exn exn:fail:contract?
             (lambda ()
               (verify #"fuzz" (crypto-random-bytes len)
                       (keypair-public kp)))
             (format "random bytes with length ~a raise contract" len)))
