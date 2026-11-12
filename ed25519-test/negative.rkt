#lang racket/base

;; Negative matrix from the release brief (section 6.3): every
;; cryptographically invalid input must yield #f from verify, and every
;; contract violation must raise exn:fail:contract. Verify must never
;; crash or raise on untrusted bytes.

(require rackunit
         racket/random
         (only-in ed25519/private/field p)
         (only-in ed25519/private/encode
                  bytes->point point->bytes bytes->scalar scalar->bytes L)
         (only-in ed25519/private/group pt-scalar-mult identity pt=?)
         ed25519
         "support/hex.rkt")

;; TEST 3 vector as the working pair.
(define secret (hex->bytes "c5aa8df43f9f837bedb7442f31dcb7b1"
                           "66d38535076f094b85ce3a2e0b4458f7"))
(define public (hex->bytes "fc51cd8e6218a1a38da47ed00230f058"
                           "0816ed13ba3303ac5deb911548908025"))
(define message (hex->bytes "af82"))
(define signature (sign message secret))
(check-equal? signature
              (hex->bytes "6291d657deec24024827e69c3abe01a3"
                          "0ce548a284743a445e3680d7db5ac3ac"
                          "18ff9b538d16f290ae67f760984dc659"
                          "4a7c15e9716ed28dc027beceea1ec40a"))
(check-true (verify message signature public))

;; --- tampered message ----------------------------------------------------

;; Every single-bit flip of the message must be rejected.
(for ([i (in-range (* 8 (bytes-length message)))])
  (define bad (bytes-copy message))
  (bytes-set! bad (quotient i 8)
              (bitwise-xor (bytes-ref bad (quotient i 8))
                           (arithmetic-shift 1 (remainder i 8))))
  (check-false (verify bad signature public)
               (format "tampered message bit ~a" i)))

;; Truncation and extension must be rejected.
(check-false (verify #"" signature public) "empty message")
(check-false (verify (bytes-append message #"x") signature public)
             "extended message")

;; --- tampered signature: every single-bit flip ---------------------------

;; Every single-bit flip anywhere in the 64-byte signature must be
;; rejected: R-half flips make R non-canonical, off-curve, or a different
;; point; S-half flips either break the equation or push S >= L.
(for ([i (in-range (* 8 64))])
  (define bad (bytes-copy signature))
  (bytes-set! bad (quotient i 8)
              (bitwise-xor (bytes-ref bad (quotient i 8))
                           (arithmetic-shift 1 (remainder i 8))))
  (check-false (verify message bad public)
               (format "tampered signature bit ~a" i)))

;; --- wrong key -------------------------------------------------------------

(check-false (verify message signature
                     (hex->bytes "d75a980182b10ab7d54bfed3c964073a"
                                 "0ee172f3daa62325af021a68f707511a"))
             "different public key must fail")

;; --- malleability: S values at and above the group order -------------------

(define s (bytes->scalar (subbytes signature 32 64)))
(define r-part (subbytes signature 0 32))

(define (sig-with-s s-value)
  (bytes-append r-part (scalar->bytes s-value)))

(check-false (verify message (sig-with-s (+ s L)) public) "S + L")
(check-false (verify message (sig-with-s L) public) "S = L")
(check-false (verify message (sig-with-s (- L 1)) public) "S = L - 1")
(check-false (verify message (sig-with-s (sub1 (expt 2 255))) public)
             "S just below 2^255")
(check-false (verify message (sig-with-s (expt 2 255)) public)
             "S = 2^255 (out of 32-byte encoding range)")

;; --- non-canonical encodings -----------------------------------------------

;; y >= p: encodings of p, p+1, p+2 and 2^255-1 (sign bit 0 where legal).
(for ([v (in-list (list p (+ p 1) (+ p 2)))] [tag (in-list '("p" "p+1" "p+2"))])
  (check-false (verify message
                       (bytes-append (scalar->bytes v) (subbytes signature 32 64))
                       public)
               (string-append "R with y = " tag))
  (check-false (verify message signature (scalar->bytes v))
               (string-append "public key with y = " tag)))

;; 2^255-1: sign bit 1 and y = 2^255-1 >= p.
(define all-ones (make-bytes 32 #xFF))
(check-false (verify message
                     (bytes-append all-ones (subbytes signature 32 64))
                     public)
             "R with y = 2^255-1, sign 1")
(check-false (verify message signature all-ones)
             "public key with y = 2^255-1, sign 1")

;; Wrong x parity: flipping the sign bit of a valid R encoding yields a
;; different point, so the equation fails.
(define flipped-sign (bytes-copy signature))
(bytes-set! flipped-sign 31
            (bitwise-xor (bytes-ref flipped-sign 31) #x80))
(check-false (verify message flipped-sign public) "R with flipped x parity")

;; x = 0 with sign bit 1 (non-canonical): y = 1 and y = p-1 with sign 1.
(check-false (verify message
                     (bytes-append (scalar->bytes (+ 1 (expt 2 255)))
                                   (subbytes signature 32 64))
                     public)
             "R with x=0, sign=1, y=1")
(check-false (verify message
                     (bytes-append (scalar->bytes (+ (- p 1) (expt 2 255)))
                                   (subbytes signature 32 64))
                     public)
             "R with x=0, sign=1, y=p-1")

;; --- small-order public keys ------------------------------------------------

;; All-zero encoding: decodes to an order-4 point; must be rejected.
(check-false (verify message signature (make-bytes 32 0)) "all-zero public key")

;; Identity point encoding (y = 1, x = 0, sign 0).
(check-false (verify message signature (scalar->bytes 1)) "identity public key")

;; Order-2 point encoding (y = p-1, x = 0, sign 0).
(check-false (verify message signature (scalar->bytes (- p 1)))
             "order-2 public key")

;; Derived small-order points: [L]P of on-curve points with order 8L.
;; Walk y = 2, 3, ... until one decodes to a point whose [L] multiple is
;; not the identity, then collect its orbit (the order-8 subgroup) and
;; reject every member as a public key.
(define small-order-encodings
  (let loop ([y 2] [encodings '()])
    (if (>= (length encodings) 4)
        encodings
        (let ([candidate (bytes->point (scalar->bytes y))])
          (cond
            [(not candidate) (loop (+ y 1) encodings)]
            [(pt=? identity (pt-scalar-mult L candidate))
             (loop (+ y 1) encodings)]
            [else
             (define q (pt-scalar-mult L candidate))
             (define orbit
               (for/list ([k (in-range 1 8)])
                 (point->bytes (pt-scalar-mult k q))))
             (loop (+ y 1) (append encodings orbit))])))))

(for ([enc (in-list small-order-encodings)])
  (check-false (verify message signature enc)
               "derived small-order public key"))

;; --- contract violations ----------------------------------------------------

;; Wrong-length signature and public key raise exn:fail:contract, never a
;; cryptographic error.
(for ([len (in-list '(0 1 31 33 63 65))])
  (check-exn exn:fail:contract?
             (lambda () (verify message (make-bytes len 1) public))
             (format "signature length ~a" len))
  (check-exn exn:fail:contract?
             (lambda () (verify message signature (make-bytes len 1)))
             (format "public key length ~a" len)))

(check-exn exn:fail:contract? (lambda () (verify "not bytes" signature public))
           "string message")
(check-exn exn:fail:contract? (lambda () (verify message "not bytes" public))
           "string signature")
(check-exn exn:fail:contract? (lambda () (verify message signature "not bytes"))
           "string public key")

;; sign/secret->public contract violations.
(check-exn exn:fail:contract? (lambda () (sign message "short")) "sign seed type")
(check-exn exn:fail:contract? (lambda () (sign message (make-bytes 31 2)))
           "sign seed length")
(check-exn exn:fail:contract? (lambda () (secret->public (make-bytes 33 3)))
           "secret->public length")
(check-exn exn:fail:contract? (lambda () (sign 42 (make-bytes 32 0)))
           "sign message type")
