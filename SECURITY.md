# Security policy

Bitseal encrypts files, so security reports matter. Thank you for reporting
problems responsibly.

## Supported versions

Only the latest release receives security fixes. Older releases are not
patched; upgrade and run `bitseal rekey` on files written by older formats.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Report it privately through GitHub:
<https://github.com/dterana/bitseal/security/advisories/new>

Useful details: the Bitseal version (`bitseal version`), what you did, what you
expected, what happened, and, if possible, a minimal encrypted file that
triggers it. Never send real passwords, key files or data.

Reports are handled on a best-effort basis by a single maintainer; there is no
guaranteed response time. If the report is valid, a fix and a security advisory
are published together with a new release, and you are credited unless you
prefer otherwise.

## Scope

In scope:

- Flaws in the cryptographic design or its use of AES-GCM, Argon2id or PBKDF2
- Ways to decrypt, forge, truncate or reorder data without the secret
- Crashes, hangs or unbounded memory use caused by a crafted encrypted file
- Leaks of secrets or plaintext (for example through output, temp files or logs)
- Writes outside the intended output path, or loss of an existing file

Out of scope:

- Weak or reused passwords (use a long passphrase and, ideally, a key file)
- An attacker who can already read the process memory or the unlocked machine
- Vulnerabilities in the Go toolchain or in dependencies that are already fixed
  upstream (Dependabot and `govulncheck` track these)
- The legacy V1 format's known limits (static salt, single block); use
  `bitseal rekey` to leave it

## How the format is protected

See [docs/format.md](docs/format.md) for the specification, the limits applied
to untrusted headers, and the rules that keep released formats readable.
