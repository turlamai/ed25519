#lang racket/base

;; Test helpers: hex <-> bytes conversion.

(provide hex->bytes bytes->hex)

(define (hex->bytes . parts)
  (define s (apply string-append parts))
  (define n (string-length s))
  (unless (even? n)
    (error 'hex->bytes "expected an even-length hex string, got: ~a" s))
  (apply bytes
         (for/list ([i (in-range 0 n 2)])
           (string->number (substring s i (+ i 2)) 16))))

(define (bytes->hex bs)
  (apply string-append
         (for/list ([b (in-bytes bs)])
           (define s (number->string b 16))
           (if (= 1 (string-length s)) (string-append "0" s) s))))
