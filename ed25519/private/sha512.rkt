#lang racket/base

;; Pure-Racket SHA-512 (FIPS 180-4).
;;
;; No FFI and no native dependency: this module exists so that Ed25519
;; works in Racket environments without any cryptographic provider.
;; Arithmetic is exact bignum arithmetic reduced mod 2^64; this is NOT
;; constant time (see the package README for the security model).

(require racket/contract
         racket/vector)

(define ((bytes-of-length n) v)
  (and (bytes? v) (= n (bytes-length v))))

(provide
 (contract-out
  [sha512 (-> bytes? (and/c bytes? (bytes-of-length 64)))]))

;; Round constants: the first 64 bits of the fractional parts of the cube
;; roots of the first 80 primes (FIPS 180-4, section 4.2.3).
(define k
  #(#x428a2f98d728ae22 #x7137449123ef65cd #xb5c0fbcfec4d3b2f #xe9b5dba58189dbbc
    #x3956c25bf348b538 #x59f111f1b605d019 #x923f82a4af194f9b #xab1c5ed5da6d8118
    #xd807aa98a3030242 #x12835b0145706fbe #x243185be4ee4b28c #x550c7dc3d5ffb4e2
    #x72be5d74f27b896f #x80deb1fe3b1696b1 #x9bdc06a725c71235 #xc19bf174cf692694
    #xe49b69c19ef14ad2 #xefbe4786384f25e3 #xfc19dc68b8cd5b5 #x240ca1cc77ac9c65
    #x2de92c6f592b0275 #x4a7484aa6ea6e483 #x5cb0a9dcbd41fbd4 #x76f988da831153b5
    #x983e5152ee66dfab #xa831c66d2db43210 #xb00327c898fb213f #xbf597fc7beef0ee4
    #xc6e00bf33da88fc2 #xd5a79147930aa725 #x6ca6351e003826f #x142929670a0e6e70
    #x27b70a8546d22ffc #x2e1b21385c26c926 #x4d2c6dfc5ac42aed #x53380d139d95b3df
    #x650a73548baf63de #x766a0abb3c77b2a8 #x81c2c92e47edaee6 #x92722c851482353b
    #xa2bfe8a14cf10364 #xa81a664bbc423001 #xc24b8b70d0f89791 #xc76c51a30654be30
    #xd192e819d6ef5218 #xd69906245565a910 #xf40e35855771202a #x106aa07032bbd1b8
    #x19a4c116b8d2d0c8 #x1e376c085141ab53 #x2748774cdf8eeb99 #x34b0bcb5e19b48a8
    #x391c0cb3c5c95a63 #x4ed8aa4ae3418acb #x5b9cca4f7763e373 #x682e6ff3d6b2b8a3
    #x748f82ee5defb2fc #x78a5636f43172f60 #x84c87814a1f0ab72 #x8cc702081a6439ec
    #x90befffa23631e28 #xa4506cebde82bde9 #xbef9a3f7b2c67915 #xc67178f2e372532b
    #xca273eceea26619c #xd186b8c721c0c207 #xeada7dd6cde0eb1e #xf57d4f7fee6ed178
    #x6f067aa72176fba #xa637dc5a2c898a6 #x113f9804bef90dae #x1b710b35131c471b
    #x28db77f523047d84 #x32caab7b40c72493 #x3c9ebe0a15c9bebc #x431d67c49c100d4c
    #x4cc5d4becb3e42b6 #x597f299cfc657e2a #x5fcb6fab3ad6faec #x6c44198c4a475817))

;; Initial hash values: the first 64 bits of the fractional parts of the
;; square roots of the first 8 primes (FIPS 180-4, section 5.3.3).
(define h-init
  #(#x6a09e667f3bcc908 #xbb67ae8584caa73b #x3c6ef372fe94f82b #xa54ff53a5f1d36f1
    #x510e527fade682d1 #x9b05688c2b3e6c1f #x1f83d9abfb41bd6b #x5be0cd19137e2179))

(define mod64 (expt 2 64))

(define (mask64 x) (modulo x mod64))

(define (shr64 x n) (arithmetic-shift x (- n)))

;; Rotate right for non-negative values below 2^64.
(define (ror64 x n)
  (bitwise-ior (arithmetic-shift x (- n))
               (arithmetic-shift x (- 64 n))))

(define (sha512 message)
  ;; FIPS 180-4 padding: append 0x80, zero-fill to 112 bytes mod 128, then
  ;; a 128-bit big-endian bit-length field.
  (define len (bytes-length message))
  (define zeros (modulo (- 111 len) 128))
  (define padded
    (bytes-append message
                  (bytes #x80)
                  (make-bytes zeros 0)
                  (make-bytes 8 0)
                  (integer->integer-bytes (* 8 len) 8 #f #t)))
  (define h (vector-copy h-init))
  (define w (make-vector 80))
  (for ([off (in-range 0 (bytes-length padded) 128)])
    (for ([i (in-range 16)])
      (vector-set! w i
                   (integer-bytes->integer
                    (subbytes padded (+ off (* 8 i)) (+ off (* 8 i) 8))
                    #f #t)))
    (for ([i (in-range 16 80)])
      (define wi-15 (vector-ref w (- i 15)))
      (define wi-2 (vector-ref w (- i 2)))
      (define s0 (bitwise-xor (ror64 wi-15 1) (ror64 wi-15 8) (shr64 wi-15 7)))
      (define s1 (bitwise-xor (ror64 wi-2 19) (ror64 wi-2 61) (shr64 wi-2 6)))
      (vector-set! w i
                   (mask64 (+ (vector-ref w (- i 16)) s0
                              (vector-ref w (- i 7)) s1))))
    (define-values (a b c d e f g hh)
      (for/fold ([a (vector-ref h 0)] [b (vector-ref h 1)]
                 [c (vector-ref h 2)] [d (vector-ref h 3)]
                 [e (vector-ref h 4)] [f (vector-ref h 5)]
                 [g (vector-ref h 6)] [hh (vector-ref h 7)])
                ([i (in-range 80)])
        (define s1 (bitwise-xor (ror64 e 14) (ror64 e 18) (ror64 e 41)))
        (define ch (bitwise-xor (bitwise-and e f)
                                (bitwise-and (bitwise-and (bitwise-not e)
                                                          (sub1 mod64))
                                             g)))
        (define t1 (mask64 (+ hh s1 ch (vector-ref k i) (vector-ref w i))))
        (define s0 (bitwise-xor (ror64 a 28) (ror64 a 34) (ror64 a 39)))
        (define maj (bitwise-xor (bitwise-and a b)
                                 (bitwise-and a c)
                                 (bitwise-and b c)))
        (define t2 (mask64 (+ s0 maj)))
        (values (mask64 (+ t1 t2)) a b c (mask64 (+ d t1)) e f g)))
    (for ([i (in-range 8)]
          [v (in-list (list a b c d e f g hh))])
      (vector-set! h i (mask64 (+ (vector-ref h i) v)))))
  (apply bytes-append
         (for/list ([word (in-vector h)])
           (integer->integer-bytes word 8 #f #t))))
