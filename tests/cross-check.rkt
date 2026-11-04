#lang racket/base

;; OpenSSL 3 cross-validation (release brief section 6.2): bidirectional,
;; randomized, batched, byte-for-byte.
;;
;; Per case, with a key pair derived from a raw Racket seed and a random
;; message:
;;   1. Racket signs; Racket verifies its own signature.
;;   2. OpenSSL signs the same message with the same key (PKCS#8 DER
;;      built here per RFC 8410); both signatures must be identical,
;;      because Ed25519 is deterministic.
;;   3. OpenSSL verifies Racket's signature.
;;
;; The test runs only when an OpenSSL 3 CLI is available; otherwise it
;; prints the reason and skips (system LibreSSL and the natipkg build
;; image's OpenSSL 1.1 lack `pkeyutl -rawin` support). Set
;; ED25519_CROSSCHECK_REQUIRE=1 to make a missing OpenSSL 3 a hard
;; failure - the dedicated CI job does this. The case count follows
;; ED25519_CROSSCHECK_CASES (default 1000, the brief's minimum).

(require racket/file
         racket/random
         rackunit
         ed25519
         "support/der.rkt"
         "support/hex.rkt"
         "support/openssl.rkt")

(define openssl (find-openssl))
(define require-openssl (getenv "ED25519_CROSSCHECK_REQUIRE"))

(define case-count
  (or (let ([env (getenv "ED25519_CROSSCHECK_CASES")])
        (and env (string->number env)))
      1000))

;; Message length cycle: 1, 2, 31, 32, 63, 64, 1024 plus a random length
;; on every eighth case. Length 0 is absent on purpose: the OpenSSL CLI
;; cannot ingest empty input files for oneshot signing ("Could not
;; allocate 0 bytes"); empty-message interoperability is already pinned
;; byte-for-byte by RFC 8032 TEST 1 in tests/rfc8032.rkt.
(define base-lengths (list 1 2 31 32 63 64 1024))

(define (case-message-length i)
  (if (zero? (modulo i 8))
      (add1 (random 2048))
      (list-ref base-lengths (modulo i (length base-lengths)))))

(define (write-bytes-to path bs)
  (call-with-output-file path
    (lambda (out) (write-bytes bs out))
    #:exists 'truncate))

(define (run-cross-check openssl-path)
  (printf "cross-check against: ~a (~a)\n"
          openssl-path (openssl-version-string openssl-path))
  (define tmp-dir (make-temporary-file "ed25519-cross~a" 'directory))
  (define msg-path (build-path tmp-dir "msg.bin"))
  (define sig-path (build-path tmp-dir "sig.bin"))
  (define key-path (build-path tmp-dir "key.pem"))
  (define pub-path (build-path tmp-dir "pub.pem"))

  ;; Reuse a pool of seeds; messages vary per case.
  (define key-count 10)
  (define seeds
    (for/list ([_ (in-range key-count)])
      (crypto-random-bytes 32)))

  (for ([i (in-range case-count)])
    (define seed (list-ref seeds (modulo i key-count)))
    (define public (secret->public seed))
    (define message (crypto-random-bytes (case-message-length i)))

    ;; 1. Racket signs and self-verifies.
    (define racket-sig (sign message seed))
    (check-true (verify message racket-sig public)
                (format "case ~a: racket self-verification" i))

    (write-bytes-to key-path
                    (string->bytes/latin-1
                     (der->pem (private-key-der seed) "PRIVATE KEY")))
    (write-bytes-to pub-path
                    (string->bytes/latin-1
                     (der->pem (public-key-der public) "PUBLIC KEY")))
    (write-bytes-to msg-path message)

    ;; 2. OpenSSL signs; signatures must be byte-identical.
    (define-values (sign-code _sign-out)
      (run-openssl openssl-path
                   (list "pkeyutl" "-sign" "-rawin"
                         "-inkey" (path->string key-path)
                         "-in" (path->string msg-path)
                         "-out" (path->string sig-path))))
    (check-equal? sign-code 0
                  (format "case ~a: openssl sign exit code" i))
    (when (zero? sign-code)
      (check-equal? (file->bytes sig-path) racket-sig
                    (format "case ~a: signatures byte-identical" i)))

    ;; 3. OpenSSL verifies Racket's signature.
    (write-bytes-to sig-path racket-sig)
    (define-values (verify-code verify-out)
      (run-openssl openssl-path
                   (list "pkeyutl" "-verify" "-rawin" "-pubin"
                         "-inkey" (path->string pub-path)
                         "-sigfile" (path->string sig-path)
                         "-in" (path->string msg-path))))
    (check-equal? verify-code 0
                  (format "case ~a: openssl verify exit code (~a)"
                          i (bytes->string/latin-1 verify-out)))

    (when (zero? (modulo (+ i 1) 100))
      (printf "  ~a/~a cases ok\n" (+ i 1) case-count)))

  (displayln
   (string-append
    "cross-check ok: " (number->string case-count)
    " cases, signatures byte-identical between pure Racket and OpenSSL 3")))

(cond
  [openssl (run-cross-check openssl)]
  [require-openssl
   (error 'cross-check
          "ED25519_CROSSCHECK_REQUIRE is set but no OpenSSL 3 CLI was found")]
  [else
   (displayln
    (string-append
     "SKIP cross-check: no OpenSSL 3 CLI found; system OpenSSL 1.1 or"
     " LibreSSL does not support Ed25519 raw signing via pkeyutl -rawin."
     " Correctness rests on the RFC 8032 vectors; this check runs for"
     " real in the dedicated CI job."))])
