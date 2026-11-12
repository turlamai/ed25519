#lang racket/base

;; Locate an OpenSSL 3 CLI with Ed25519 support and run it in a controlled
;; way. System LibreSSL (macOS) and OpenSSL 1.1 (natipkg build images) do
;; not support `pkeyutl -rawin` Ed25519 and are deliberately excluded so
;; the cross-check skips instead of failing or, worse, passing vacuously.

(require racket/path
         racket/port
         racket/string
         racket/system)

(provide find-openssl
         run-openssl
         openssl-version-string)

(define (candidate-paths)
  (append
   (let ([env (getenv "ED25519_OPENSSL")])
     (if env (list env) '()))
   '("openssl3"
     "openssl"
     "/usr/bin/openssl"
     "/usr/local/bin/openssl"
     "/opt/homebrew/bin/openssl"
     "/opt/homebrew/opt/openssl@3/bin/openssl"
     "/usr/local/opt/openssl@3/bin/openssl"
     "/mingw64/bin/openssl.exe"
     "C:/Program Files/OpenSSL-Win64/bin/openssl.exe")))

;; subprocess returns (values process stdout-port stdin-port stderr-port):
;; the ports follow the parameter order (stdout, stdin, stderr).
(define (openssl-version-string path)
  (with-handlers ([exn:fail? (lambda (_) "")])
    (parameterize ([current-subprocess-custodian-mode 'kill])
      (define-values (proc stdout stdin stderr)
        (subprocess #f #f #f path "version"))
      (close-output-port stdin)
      (define out (string-trim (port->string stdout)))
      (close-input-port stdout)
      (close-input-port stderr)
      (subprocess-wait proc)
      out)))

;; Accept only "OpenSSL 3.x" version banners. LibreSSL and OpenSSL 1.1
;; return #f.
(define (openssl3? path)
  (string-prefix? (openssl-version-string path) "OpenSSL 3"))

(define (find-openssl)
  (for/or ([cand (in-list (candidate-paths))])
    (cond
      [(not cand) #f]
      [(absolute-path? cand)
       (and (file-exists? cand) (openssl3? cand) cand)]
      [else
       (define found (find-executable-path cand))
       (and found (openssl3? found) (path->string found))])))

;; Run openssl with the given arguments; optional stdin bytes. Returns
;; (values exit-code stdout-bytes).
(define (run-openssl path args #:stdin [stdin-bytes #f])
  (parameterize ([current-subprocess-custodian-mode 'kill])
    (define-values (proc stdout stdin stderr)
      (apply subprocess #f #f #f path args))
    (when stdin-bytes
      (write-bytes stdin-bytes stdin)
      (close-output-port stdin))
    (define out (port->bytes stdout))
    (close-input-port stdout)
    (close-input-port stderr)
    (subprocess-wait proc)
    (values (subprocess-status proc) out)))
