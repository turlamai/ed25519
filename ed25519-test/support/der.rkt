#lang racket/base

;; PKCS#8 / SPKI DER wrappers for Ed25519 raw keys (RFC 8410), used by the
;; OpenSSL cross-check to hand raw Racket seeds and public keys to the
;; OpenSSL CLI.
;;
;; PrivateKeyInfo:
;;   SEQUENCE {
;;     INTEGER 0
;;     SEQUENCE { OID 1.3.101.112 }           ; id-Ed25519
;;     OCTET STRING { OCTET STRING (32 bytes) } ; the seed
;;   }                                        ; header: 302e020100300506032b657004220420
;; SubjectPublicKeyInfo:
;;   SEQUENCE {
;;     SEQUENCE { OID 1.3.101.112 }
;;     BIT STRING (32 bytes)                  ; header: 302a300506032b6570032100
;;   }

(require net/base64
         racket/string
         "hex.rkt")

(provide private-key-der
         public-key-der
         der->pem)

(define pkcs8-prefix (hex->bytes "302e020100300506032b657004220420"))
(define spki-prefix (hex->bytes "302a300506032b6570032100"))

(define (private-key-der seed)
  (unless (and (bytes? seed) (= 32 (bytes-length seed)))
    (error 'private-key-der "expected a 32-byte seed"))
  (bytes-append pkcs8-prefix seed))

(define (public-key-der public)
  (unless (and (bytes? public) (= 32 (bytes-length public)))
    (error 'public-key-der "expected a 32-byte public key"))
  (bytes-append spki-prefix public))

(define (der->pem der label)
  ;; base64-encode wraps at 64 chars using the given newline characters,
  ;; matching PEM line conventions.
  (define b64 (bytes->string/latin-1 (base64-encode der #"\n")))
  (string-append
   "-----BEGIN " label "-----\n"
   (string-trim b64 "\n" #:right? #t)
   "\n-----END " label "-----\n"))
