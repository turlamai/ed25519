#lang racket/base

;; Twisted Edwards curve  -x^2 + y^2 = 1 + d x^2 y^2  over GF(2^255 - 19).
;;
;; Points use extended homogeneous coordinates (X : Y : Z : T) with
;; x = X/Z, y = Y/Z and x*y = T/Z (RFC 8032, section 5.1.2). The addition
;; formulas are the complete, unified ones from RFC 8032 section 5.1.4
;; (Hisil–Wong–Carter–Dawson, "a = -1"), so the same routine handles
;; identity, doubling, and arbitrary point pairs without special cases.

(require "field.rkt")

(provide pt
         pt-x pt-y pt-z pt-t
         identity
         base-point
         pt-add
         pt-scalar-mult
         pt=?
         small-order?)

(struct pt (x y z t) #:transparent)

(define identity (pt 0 1 1 0))

;; Base point B: y = 4/5 mod p with the canonical even x (RFC 8032,
;; section 5.1). Both coordinates are derived from the curve parameters;
;; nothing is transcribed from external tables.
(define base-y (fmul 4 (finv 5)))
(define base-x (recover-x base-y))
(unless base-x
  (error 'ed25519 "internal error: base point is not on the curve"))
(define base-point (pt base-x base-y 1 (fmul base-x base-y)))

;; Complete unified addition (RFC 8032 section 5.1.4):
;;   A = (Y1-X1)(Y2-X2)     B = (Y1+X1)(Y2+X2)
;;   C = 2 d T1 T2          D = 2 Z1 Z2
;;   E = B-A  F = D-C  G = D+C  H = B+A
;;   X3 = E F   Y3 = G H   T3 = E H   Z3 = F G
(define (pt-add p1 p2)
  (define x1 (pt-x p1))
  (define y1 (pt-y p1))
  (define z1 (pt-z p1))
  (define t1 (pt-t p1))
  (define x2 (pt-x p2))
  (define y2 (pt-y p2))
  (define z2 (pt-z p2))
  (define t2 (pt-t p2))
  (define a (fmul (fsub y1 x1) (fsub y2 x2)))
  (define b (fmul (fadd y1 x1) (fadd y2 x2)))
  (define c (fmul (fmul t1 d2) t2))
  (define dd (fmul (fadd z1 z1) z2))
  (define e (fsub b a))
  (define f (fsub dd c))
  (define g (fadd dd c))
  (define h (fadd b a))
  (pt (fmul e f) (fmul g h) (fmul f g) (fmul e h)))

;; Left-to-right double-and-add over the bignum scalar. The unified
;; addition doubles as the doubling step; this is deliberately simple and
;; regular. It is NOT constant time and makes no claim to be.
(define (pt-scalar-mult n point)
  (unless (and (integer? n) (not (negative? n)))
    (raise-argument-error 'pt-scalar-mult "nonnegative exact integer?" n))
  (if (zero? n)
      identity
      (let loop ([i (- (integer-length n) 1)] [acc identity])
        (if (< i 0)
            acc
            (let* ([acc2 (pt-add acc acc)]
                   [acc2 (if (bitwise-bit-set? n i) (pt-add acc2 point) acc2)])
              (loop (sub1 i) acc2))))))

;; Equality without inverting Z, by cross-multiplication.
(define (pt=? p1 p2)
  (and (= (fmul (pt-x p1) (pt-z p2)) (fmul (pt-x p2) (pt-z p1)))
       (= (fmul (pt-y p1) (pt-z p2)) (fmul (pt-y p2) (pt-z p1)))))

;; A point has small order (1, 2, 4 or 8) exactly when multiplying by 8
;; yields the identity: the curve group has order 8L with L prime, so any
;; point of order dividing 8 is annihilated by 8, while points of order
;; L, 2L, 4L or 8L are not.
(define (small-order? point)
  (pt=? identity (pt-scalar-mult 8 point)))
