# Threat model

This page states what Casemate protects, against whom, and what it does not
cover. It is meant for someone deciding whether Casemate fits their data. The
file layout itself is in [format.md](format.md). Casemate has not had an
independent audit; this document is the maintainer's own analysis.

## What Casemate is for

Encrypting files at rest with a password, optionally plus a key file, so that
someone who gets the encrypted file (a backup bucket, a stolen laptop, a cloud
drive, an email attachment) cannot read or silently change its contents.

## Assets

| Asset | Protected by |
|---|---|
| Plaintext contents | AES-256-GCM, key derived from the password (and key file) with Argon2id |
| Integrity of the contents | GCM tags on every chunk, nonces that encode position and finality |
| Password and key file | Never written to disk by Casemate; zeroed after use (best effort) |

## Attackers considered

### 1. Someone who obtains the encrypted file

Casemate is designed for this attacker.

- **Reading the plaintext:** requires guessing the password. Argon2id
  (3 passes, 64 MiB, 4 threads by default) makes each guess expensive, but a
  guessable password still falls. A key file adds a second factor that the
  attacker also needs.
- **Modifying the file:** any change to a chunk, the header, the chunk order or
  the length fails authentication. This includes truncating at a chunk boundary
  and swapping the KDF parameters in the header.
- **Crafted files:** header values are bounded (at most 1 GiB of KDF memory and
  64 passes), unknown versions and flags are refused, and `info` never needs the
  password. Fuzz tests exercise the parsers.

### 2. Someone who can run Casemate on hostile input

A hostile encrypted file must not crash Casemate, exhaust memory, write
outside the chosen output path, or release unauthenticated plaintext. Decrypted
data goes to a temporary file that is renamed into place only after the last
chunk authenticated; to stdout it is held back until then.

### 3. Someone who can observe the machine while Casemate runs

Only partially covered. See "Not protected" below.

## What an attacker still learns

Encryption does not hide everything. Someone holding the file can see:

- **The file exists, and roughly how big the plaintext is.** The ciphertext
  length is the plaintext length plus 35 bytes of header and 16 bytes per
  64 KiB chunk, so the size is recoverable exactly.
- **The format version, the KDF cost and whether a key file is required.** These
  are in the unencrypted header.
- **Whatever you put in the file name.** The default name is the input name
  plus `.enc`. Rename files if the name is sensitive.
- **Timestamps and permissions of the file on disk**, which belong to the
  filesystem, not to Casemate.

## Not protected

- **A weak or reused password.** This is the main risk. Use a long passphrase
  and, ideally, a key file.
- **A compromised machine.** Malware, a keylogger, or anyone who can read the
  process memory, swap or a core dump can get the password or plaintext.
  Casemate zeroes its own buffers, but Go and the terminal layer may keep other
  copies, and memory is not locked against swapping.
- **Plaintext left behind.** Casemate never deletes the original file after
  encrypting. Decrypted output and any copies are your responsibility.
- **Who wrote the file.** GCM proves the file was produced by someone holding
  the password, not by a specific person. Use signatures if you need authorship.
- **Freshness.** An attacker who has an older valid encrypted file can put it
  back in place of the newer one. Nothing in the file says which version is
  current.
- **Key commitment.** AES-GCM does not bind a ciphertext to a single key. In
  principle a file can be built that decrypts under two different passwords.
  This matters for systems that treat decryption success as proof of identity;
  it does not enable reading a file without the password.
- **Forward secrecy.** There is one long-lived secret. If the password leaks,
  every file encrypted with it is readable. `casemate rekey` changes the
  password but cannot revoke copies of the old file.
- **The legacy V1 format.** It uses a static salt and a single block. Run
  `casemate rekey` to leave it.
- **Compromised dependencies or toolchain.** Releases ship with SBOMs and build
  provenance (`gh attestation verify`), which helps you check what you
  installed. They do not prove the source is free of bugs.

## Design choices that follow from this

| Choice | Reason |
|---|---|
| Argon2id with per-file random salt | Slows offline guessing and defeats precomputed tables |
| Parameters stored in the header | Costs can be raised later; old files keep decrypting |
| Whole header authenticated in every chunk | No downgrade or parameter swapping |
| Nonce encodes chunk index and "last" | Reordering, dropping and truncation fail |
| Temp file plus rename, stdout held back | No unauthenticated plaintext reaches a file or pipe |
| Refuse unknown versions and flags | A reader never guesses |
| No Casemate-specific secret storage | The password comes from you; use your secret store |

## Reporting a problem

If you find a gap in this model, report it privately as described in
[SECURITY.md](../SECURITY.md).
