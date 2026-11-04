#lang info

;; Collection-level info: `raco setup` discovers documentation only from
;; the `scribblings` field of a collection's own info.rkt; for
;; `collection 'multi` packages a package-root declaration is never
;; consulted when rendering.
(define collection "ed25519")
(define scribblings '(("scribblings/ed25519.scrbl" () (library))))
