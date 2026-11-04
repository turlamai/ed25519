#lang racket/base

;; 32-byte Ed25519 point and scalar encodings with canonical validation.
;;
;; A point encoding is 32 bytes: the y coordinate little-endian in the low
;; 255 bits and the parity (low bit) of x in bit 255. Decoding rejects any
;; non-canonical or off-curve encoding by returning #f:
;;
;;   - y >= p            (the integer encoding is out of field range)
;;   - x not recoverable (the implied x^2 is a non-residue: off curve)
;;   - x = 0 with sign 1 (x = 0 has no odd root: non-canonical sign)

(require "field.rkt"
         "group.rkt")

(provide bytes->point
         point->bytes
         bytes->scalar
         scalar->bytes
         L)

;; Group order L = 2^252 + 27742317777372353535851937790883648493
;; (RFC 8032, section 5.1).
(define L (+ (expt 2 252) 27742317777372353535851937790883648493))

;; Little-endian 32-byte <-> integer. Racket's integer->integer-bytes and
;; integer-bytes->integer are limited to 1/2/4/8-byte strings, so these
;; work byte by byte.
(define (bytes->scalar encoded)
  (for/fold ([acc 0])
            ([b (in-bytes encoded)] [i (in-naturals)])
    (bitwise-ior acc (arithmetic-shift b (* 8 i)))))

(define (scalar->bytes scalar)
  (define out (make-bytes 32))
  (for ([i (in-range 32)])
    (bytes-set! out i
                (bitwise-and (arithmetic-shift scalar (* -8 i)) #xFF)))
  out)

(define (point->bytes point)
  (define zi (finv (pt-z point)))
  (define x (fmul (pt-x point) zi))
  (define y (fmul (pt-y point) zi))
  (define out (scalar->bytes y))
  ;; y < p < 2^255 leaves bit 255 free; store the parity of x there.
  (bytes-set! out 31
              (bitwise-ior (bytes-ref out 31)
                           (arithmetic-shift (bitwise-and x 1) 7)))
  out)

;; Decode a 32-byte point encoding; #f for anything non-canonical or
;; off-curve. Accepts any bytes? and never raises on bad input.
(define (bytes->point encoded)
  (and (bytes? encoded)
       (= 32 (bytes-length encoded))
       (let* ([encoded-int (bytes->scalar encoded)]
              [sign (arithmetic-shift encoded-int -255)]
              [y (bitwise-and encoded-int (sub1 (expt 2 255)))]
              [x (and (< y p) (recover-x y))])
         (and x
              (let* ([x (if (= sign (bitwise-and x 1)) x (fsub p x))]
                     [ok (not (and (zero? x) (= sign 1)))])
                (and ok (pt x y 1 (fmul x y))))))))
