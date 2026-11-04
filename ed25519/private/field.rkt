#lang racket/base

;; GF(2^255 - 19) field arithmetic on exact bignums in [0, p).
;;
;; Bignum operations are not constant time; this module makes no
;; side-channel promise (see the package README).

(provide fp
         fadd fsub fneg fmul fsqr
         fpow finv
         p d d2 sqrtm1
         recover-x)

(define p (- (expt 2 255) 19))

(define (fp x) (modulo x p))
(define (fadd a b) (modulo (+ a b) p))
(define (fsub a b) (modulo (- a b) p))
(define (fneg a) (if (zero? a) 0 (fsub p a)))
(define (fmul a b) (modulo (* a b) p))
(define (fsqr a) (modulo (* a a) p))

;; base^e mod p by square-and-multiply, e >= 0.
(define (fpow base e)
  (let loop ([r 1] [b (modulo base p)] [e e])
    (cond
      [(zero? e) r]
      [(even? e) (loop r (fsqr b) (arithmetic-shift e -1))]
      [else (loop (fmul r b) (fsqr b) (arithmetic-shift e -1))])))

(define (finv a) (fpow a (- p 2)))

;; Curve constant d = -121665/121666 mod p (RFC 8032, section 5.1).
(define d (fsub 0 (fmul 121665 (finv 121666))))
(define d2 (fadd d d))

;; sqrt(-1) mod p; exists because p = 2^255 - 19 = 1 (mod 4).
(define sqrtm1 (fpow 2 (quotient (- p 1) 4)))

;; Recover the canonical (even) x for a curve point given y, following the
;; ref10 decompression technique used by the Ed25519 reference
;; implementation (public domain, D. J. Bernstein et al.):
;;
;;   x^2 = (y^2 - 1) / (d y^2 + 1)
;;   x   = u v^3 (u v^7)^((p-5)/8)   with u = y^2 - 1, v = d y^2 + 1
;;
;; Returns #f when x^2 has no solution, i.e. the point (x, y) is not on
;; the curve. Returns the even root so callers can flip parity to match a
;; recovered sign bit.
(define (recover-x y)
  (define yy (fsqr y))
  (define u (fsub yy 1))
  (define v (fadd (fmul d yy) 1))
  (define cand
    (fmul (fmul u (fpow v 3))
          (fpow (fmul u (fpow v 7)) (quotient (- p 5) 8))))
  (define vxx (fmul v (fsqr cand)))
  (define x
    (cond
      [(= vxx u) cand]
      [(= vxx (fsub 0 u)) (fmul cand sqrtm1)]
      [else #f]))
  (and x
       (if (even? x) x (fsub p x))))
