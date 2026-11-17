module github.com/dterana/casemate

go 1.26.2

retract [v0.1.0, v0.5.0] // Republished from a clean history, use v0.6.0 or later

require (
	golang.org/x/crypto v0.59.0
	golang.org/x/term v0.48.0
)

require golang.org/x/sys v0.50.0 // indirect
