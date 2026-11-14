# Bitseal

A future-proof file encryption CLI tool in Go with versioned encryption algorithms for long-term data protection.

## Overview

Bitseal is a lightweight command-line utility for encrypting and decrypting files with automatic version management. Unlike tools like OpenSSL that change their defaults and break backward compatibility, Bitseal embeds version information in every encrypted file, allowing it to decrypt old files even after algorithm changes.

**Why Bitseal?**
- 🔒 **Future-proof**: Version your encryption. Decrypt old files forever, even after updating algorithms
- 🎯 **Simple**: Single-purpose tool focused on file encryption
- 🔐 **Secure**: AES-256-GCM with Argon2id key derivation, per-file salts, optional key file and hidden password input
- 🌊 **Streaming**: Chunked format, so large files use bounded memory and can flow through pipes
- 🧰 **Scriptable**: Password from a file or environment variable, stdin/stdout support, quiet stdout
- 🚀 **Easy to extend**: Interface-based design makes adding new cipher versions trivial
- 📦 **Minimal dependencies**: Go standard library plus `golang.org/x/crypto` and `golang.org/x/term`

## Installation

### From a release
Download the archive for your platform from the GitHub releases page and put `bitseal` on your `PATH`.

### From source
Building requires Go 1.26 or newer (set by the `golang.org/x/crypto` dependency).
```bash
git clone https://github.com/dterana/bitseal.git
cd bitseal
make build        # embeds the git revision in `bitseal version`
```

### Using go install
```bash
go install github.com/dterana/bitseal@latest
```

## Usage

```
bitseal encrypt [flags] [file...]   Encrypt files (writes <file>.enc)
bitseal decrypt [flags] [file...]   Decrypt files (strips .enc)
bitseal rekey   [flags] [file...]   Re-encrypt files in place with the current format,
                                    optionally with a new password or key file
bitseal info    [file...]           Show a file's format without decrypting it
bitseal version                     Show version information
```

Put flags before the file names. Exit codes: `0` success, `1` an operation failed, `2` invalid flags.

### Encrypt and decrypt
```bash
./bitseal encrypt myfile.txt              # creates myfile.txt.enc
./bitseal decrypt myfile.txt.enc          # restores myfile.txt
./bitseal encrypt -file a.txt -file b.txt # several files, one password prompt
./bitseal encrypt -file myfile.txt -out secure.bin
./bitseal decrypt -file secure.bin -out recovered.txt
```

On a terminal, `encrypt` asks for the password twice so a typo cannot lock you out of your own file.

Decrypting a file that does not end in `.enc` requires `-out`, and the output path must differ from the input path. Bitseal refuses both cases instead of overwriting your encrypted file. Directories are not supported; archive them first (for example with `tar`).

### Where the password comes from

| Source | How |
|---|---|
| Terminal prompt | default when stdin is a terminal (hidden input) |
| Pipe | the first line of stdin, when stdin is not a terminal |
| File | `-password-file <path>`, first line of the file |
| Environment | `-password-env <NAME>` |

```bash
echo "mypassword" | ./bitseal encrypt secret.txt          # piped (visible in shell history)
./bitseal decrypt -password-file ~/.secrets/pw  -out - config.yml.enc
BITSEAL_PASSWORD=... ./bitseal decrypt -password-env BITSEAL_PASSWORD config.yml.enc
```

Spaces inside a password are kept (`correct horse battery staple` works); surrounding whitespace and the line ending are trimmed. A password file that other users can read produces a warning. Prefer `-password-file` or `-password-env` over `echo`, which exposes the password in shell history and process listings.

### Key file (second factor)
```bash
./bitseal encrypt -keyfile ~/.keys/seal.key notes.txt
./bitseal decrypt -keyfile ~/.keys/seal.key notes.txt.enc
```
The key file is hashed and mixed into the key together with the password, so an attacker needs both. The file records that a key file is required, so decrypting without one gives a clear error. Key files need format V2.

### stdin and stdout
Use `-` for stdin (`-file -`) or stdout (`-out -`). Data goes to stdout; prompts, progress and errors go to stderr, so pipelines stay clean.

```bash
tar czf - ./project | ./bitseal encrypt -password-file pw -file - -out project.tar.gz.enc
./bitseal decrypt -password-file pw -file project.tar.gz.enc -out - | tar xzf -
```

- With `-file -` the password cannot come from stdin; use `-password-file` or `-password-env`.
- `encrypt` refuses to write binary output to a terminal.
- `decrypt -out -` holds the plaintext back until the whole file has authenticated, so a corrupt file prints nothing. This buffers the plaintext in memory; for very large files decrypt to a file instead.

### Upgrade or change a file with `rekey`
```bash
./bitseal info old.enc                       # shows "Version: 1 ... legacy"
./bitseal rekey old.enc                      # same password, current format, atomic in place
./bitseal rekey -change-password a.enc       # prompts for the current and the new password
./bitseal rekey -new-password-file new.pw a.enc
./bitseal rekey -new-keyfile seal.key a.enc  # add or replace the key file
./bitseal rekey -no-keyfile a.enc            # remove the key file requirement
./bitseal rekey -out b.enc a.enc             # write elsewhere, keep the original
```
The plaintext is piped between decrypting and re-encrypting and never touches the disk. A failure leaves the original file untouched. A key file given with `-keyfile` is the current one; use `-new-keyfile` to change it.

### Inspect a file
```
$ ./bitseal info notes.txt.enc
File:      notes.txt.enc
Version:   2
Cipher:    AES-256-GCM (chunked), 64 KiB chunks
KDF:       Argon2id (time=3, memory=64 MiB, threads=4), random per-file salt
Key file:  not required
```
`info` reads only the header and needs no password.

## How It Works

### Security Features

**Encryption**: AES-256 in GCM mode provides authenticated encryption, protecting against tampering and detecting corrupted files.

**Key Derivation**: New files (V2) use Argon2id (3 passes, 64 MiB, 4 threads) with a random 16-byte per-file salt. The parameters are stored in each file's header, so the defaults can be raised later without a new cipher version, and old files keep decrypting with the parameters they were written with. Parameters read from a file are bounded (at most 1 GiB of memory), so a hostile file cannot make Bitseal exhaust memory.

**Chunked authentication**: V2 splits data into 64 KiB chunks. Each chunk's nonce encodes its position and whether it is the last one, so reordering, duplicating, dropping or truncating chunks is detected, including truncation at a chunk boundary. The whole header is authenticated as additional data of every chunk.

**Atomic Writes**: Output is written to a temporary file in the destination directory and renamed into place, so a failed run never truncates or half-writes an existing file. An interrupt (Ctrl+C) or SIGTERM removes the temporary file.

**Password Input**: The password is read with terminal echo disabled, so nothing appears on screen as you type.

### File Format

```
V2: [version=2:1] [flags:1] [chunk size exponent:1] [Argon2 time:4] [Argon2 memory KiB:4]
    [Argon2 threads:1] [salt:16] [nonce prefix:7] [chunk 1] [chunk 2] ... [final chunk]
    each chunk = up to 2^exponent bytes of data + 16 byte GCM tag
    flags bit 0 = a key file is required

V1: [version=1:1] [nonce:12] [encrypted data + tag]      (legacy, decrypt only)
```

V1 uses PBKDF2-SHA256 (100,000 iterations) with a static salt. It is still decrypted automatically; use `rekey` to upgrade V1 files.

The version byte allows Bitseal to automatically route decryption to the correct algorithm, even as new versions are added.

## Why Version Your Encryption?

The OpenSSL problem: In 2023, OpenSSL changed its default digest from MD5 to SHA-256 for `enc` command. If you had encrypted files with the old version, you couldn't decrypt them anymore without specifying legacy parameters.

Bitseal solves this by embedding the version number in every encrypted file. When you decrypt, it automatically detects which algorithm was used and applies it, no matter how many new versions have been released.

## Architecture

The codebase is organized for easy maintenance and extension:

- **main.go**: CLI entry point, commands and flags
- **crypto.go**: `CipherVersion` and `StreamCipher` interfaces, `Secret`, and the legacy V1 cipher
- **crypto_v2.go**: V2 cipher (chunked AES-GCM, Argon2id, header handling)
- **cipher_manager.go**: Version detection, file operations, rekey and inspect
- **fileio.go**: Atomic writes, temp file tracking and signal cleanup
- **password.go**: Password prompt, pipe, file, environment and key file input
- **version.go**: Version and build information

### Adding a New Cipher Version

1. Create a new cipher implementation (see `crypto_v2.go`) implementing `CipherVersion`, and `StreamCipher` if it can stream:
```go
type CipherV3 struct { /* ... */ }

func (c *CipherV3) Version() byte { return 3 }
func (c *CipherV3) Encrypt(plaintext []byte, secret Secret) ([]byte, error) { /* ... */ }
func (c *CipherV3) Decrypt(ciphertext []byte, secret Secret) ([]byte, error) { /* ... */ }
func (c *CipherV3) Inspect(src io.Reader) (FileInfo, error) { /* ... */ }
```

2. Register it in `cipher_manager.go`:
```go
ciphers: map[byte]CipherVersion{
    1: NewCipherV1(),
    2: newCipherV2With(kdf, chunkLog2),
    3: NewCipherV3(),  // New!
}
```

3. Set `CurrentVersion` in `cipher_manager.go` to `3` so new files use it, and add golden vectors for the new version in `golden_test.go`.

That's it! Files encrypted with older versions will still decrypt automatically, and `rekey` upgrades them.

## Security Considerations

- **Password Strength**: Use strong passwords (16+ characters, or a long passphrase). A weak password is the weakest link; Argon2id slows guessing but cannot save a guessable password. A key file adds a second factor.
- **Salt**: V2 uses a random per-file salt stored in the header. V1 files use a static salt; upgrade them with `bitseal rekey`.
- **File Permissions**: Output files are created with 0600 permissions (read/write only by owner).
- **Authentication scope**: The tool encrypts and authenticates files with the password, but a file cannot prove who wrote it. For that, use signatures alongside encrypted files.
- **Password in memory**: Bitseal zeroes its own copies of the password and key file after use. This is best effort: Go and the terminal layer may keep other copies until the process exits.

## Limitations

- **Interrupted runs**: Output is written to a `.bitseal-*.tmp` file next to the destination and renamed on success. Ctrl+C and SIGTERM remove it, but if the process is killed with SIGKILL the temp file can remain and is safe to delete.
- **Buffered stdout decrypt**: `decrypt -out -` and V1 files are held in memory while decrypting (V2 to a file streams with bounded memory).
- **No directories**: Bitseal encrypts single files or streams. Archive directories first.
- **No Keychain integration**: Use `-password-file` or `-password-env` to feed a password from your secret store.

## Examples

### Encrypt sensitive notes
```bash
./bitseal encrypt notes.txt
# Enter password when prompted (twice)
```

### Batch encryption
```bash
./bitseal encrypt *.doc
```

### Backup and encrypt
```bash
tar czf - /path/to/data | ./bitseal encrypt -password-file ~/.pw -file - -out backup.tar.gz.enc
```

### Render a secret config at setup time
```bash
./bitseal decrypt -password-env BITSEAL_PASSWORD -out ~/.config/ngrok/ngrok.yml secrets/ngrok.yml.enc
```

## Troubleshooting

**"decryption failed (wrong password or corrupted file)"**
- Check that you entered the correct password (and key file, if one was used)
- Verify the file hasn't been corrupted or tampered with

**"this file requires a key file (-keyfile)"** / **"this file was not encrypted with a key file"**
- Pass `-keyfile` exactly when the file was encrypted with one; `bitseal info` shows whether it is required

**"cannot infer output path: input does not end in .enc, use -out"**
- Pass `-out <path>` to say where the decrypted file should go

**"output path must differ from input path"**
- Choose a different `-out`; Bitseal never writes over the file it is reading

**"passwords do not match"**
- The two prompts on `encrypt` differed; run the command again

**"cannot read the password from stdin while the input is stdin"**
- With `-file -`, use `-password-file` or `-password-env`

**"refusing to write encrypted data to a terminal"**
- Use `-out <file>` or redirect stdout

**"unsupported encryption version"** / **"unsupported file flags"**
- Your encrypted file uses a newer format than your Bitseal build; update Bitseal

**Password input not hidden**
- This can happen when input is redirected; Bitseal then reads the first line from stdin

## Development

### Running tests
```bash
make test         # unit, CLI and end-to-end tests (the end-to-end tests build the binary)
make test-short   # skips the large-file cases
make test-race    # with the race detector
make cover        # per-function coverage
make fuzz         # fuzz each target for FUZZTIME (default 20s)
```

The suite covers both cipher versions (round trips, wrong passwords, tampering at every byte, truncation at every length, chunk reordering and duplication, golden vectors that lock the on-disk formats), the file operations (atomic writes, refusal to overwrite the input, stdin/stdout, rekey, info), every password source, the CLI in-process, and the compiled binary end to end including a real SIGINT. Fuzz targets cover the decryptors and the header parser.

### Building
```bash
make build
```

### Formatting
```bash
go fmt ./...
```

### Continuous integration and releases
`.github/workflows/ci.yml` checks formatting, runs `go vet` and `go test -race` with coverage on Linux and macOS, fuzzes each target briefly, and runs `govulncheck` on every push to `main` or `staging` and on every pull request.

Pushing a tag like `v0.1.0` runs `.github/workflows/release.yml`, which tests and publishes binaries with GoReleaser (`.goreleaser.yaml`).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see the LICENSE file for details

## Disclaimer

This tool is provided as-is. While it uses well-established cryptographic algorithms, no security tool is perfect. For highly sensitive data, consider using established tools like GPG or encrypting filesystems. Always test on non-critical data first and maintain secure backups of your passwords.
