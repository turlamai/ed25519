#lang racket/base

;; Property tests from the release brief (section 6.4): determinism,
;; secret->public consistency, roundtrip success, and rejection of
;; modified messages across key pairs and message sizes.

(require rackunit
         racket/random
         ed25519)

(define message-lengths (list 0 1 31 32 63 64 1024 2048))

(define keypairs
  (for/list ([i (in-range 20)])
    (generate-keypair)))

;; keypair accessors and transparency
(for ([kp (in-list keypairs)])
  (check-equal? (bytes-length (keypair-public kp)) public-key-length)
  (check-equal? (bytes-length (keypair-secret kp)) secret-key-length)
  (check-equal? (keypair-public kp) (ed25519-keypair-public kp))
  (check-equal? (secret->public (keypair-secret kp)) (keypair-public kp)
                "secret->public agrees with the keypair's public key"))

;; the same seed yields equal (transparent) keypairs
(define seed (make-bytes 32 7))
(check-equal? (ed25519-keypair (secret->public seed) seed)
              (ed25519-keypair (secret->public seed) seed)
              "same seed yields equal keypairs")
;; fresh keypairs are independent
(check-false (equal? (generate-keypair) (generate-keypair))
             "fresh keypairs differ (32-byte OS entropy)")

(for ([kp (in-list keypairs)]
      [len (in-cycle message-lengths)]
      [i (in-naturals)])
  (define message (crypto-random-bytes len))
  (define pk (keypair-public kp))
  (define sk (keypair-secret kp))
  (define sig (sign message sk))

  ;; deterministic: two calls agree byte for byte
  (check-equal? (sign message sk) sig "sign is deterministic")

  ;; roundtrip
  (check-true (verify message sig pk) "roundtrip verification")

  ;; any modified message fails
  (when (> len 0)
    (define bad (bytes-copy message))
    (bytes-set! bad (sub1 len) (bitwise-xor (bytes-ref bad (sub1 len)) 1))
    (check-false (verify bad sig pk) "modified message fails"))

  ;; wrong length public key from a different pair fails
  (let ([other (list-ref keypairs (modulo (+ i 1) (length keypairs)))])
    (unless (equal? other kp)
      (check-false (verify message sig (keypair-public other))
                   "other keypair fails"))))

;; constants are what the docs say
(check-equal? public-key-length 32)
(check-equal? secret-key-length 32)
(check-equal? signature-length 64)
