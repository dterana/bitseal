# Bitseal

A future-proof file encryption CLI tool in Go with versioned encryption algorithms for long-term data protection.

## Overview

Bitseal is a lightweight command-line utility for encrypting and decrypting files with automatic version management. Unlike tools like OpenSSL that change their defaults and break backward compatibility, Bitseal embeds version information in every encrypted file, allowing it to decrypt old files even after algorithm changes.

**Why Bitseal?**
- 🔒 **Future-proof**: Version your encryption. Decrypt old files forever, even after updating algorithms
- 🎯 **Simple**: Single-purpose tool focused on file encryption
- 🔐 **Secure**: AES-256-GCM with Argon2id key derivation, per-file salts and hidden password input
- 🚀 **Easy to extend**: Interface-based design makes adding new cipher versions trivial
- 📦 **Minimal dependencies**: Uses only Go standard library and `golang.org/x/term` and `golang.org/x/crypto`

## Installation

### From source
```bash
git clone https://github.com/dterana/bitseal.git
cd bitseal
go build -o bitseal
```

### Using go install
```bash
go install github.com/dterana/bitseal@latest
```

## Usage

### Encrypt a file
```bash
./bitseal encrypt -file myfile.txt
# Creates: myfile.txt.enc
```

### Decrypt a file
```bash
./bitseal decrypt -file myfile.txt.enc
# Restores: myfile.txt
```

### Custom output path
```bash
./bitseal encrypt -file myfile.txt -out secure.bin
./bitseal decrypt -file secure.bin -out recovered.txt
```

Decrypting a file that does not end in `.enc` requires `-out`, and the output path must differ from the input path. Bitseal refuses both cases instead of overwriting your encrypted file.

### Usage with pipes (non-interactive)
```bash
# Password can be piped in (less secure, use only in scripts)
echo "mypassword" | ./bitseal encrypt -file secret.txt
```

When piped, the first line of stdin is the password. Spaces inside it are kept (`correct horse battery staple` works) and surrounding whitespace and the line ending are trimmed. Piped input is read once, so there is no confirmation prompt.

## How It Works

### Security Features

**Encryption**: AES-256 in GCM mode provides authenticated encryption, protecting against tampering and detecting corrupted files.

**Key Derivation**: New files (V2) use Argon2id (3 passes, 64 MiB, 4 threads) with a random 16-byte per-file salt. V1 files used PBKDF2-SHA256 (100,000 iterations) with a static salt and remain decryptable.

**Random Nonce**: Each encryption uses a fresh random 12-byte nonce, so encrypting the same file twice produces completely different output.

**Password Confirmation**: On a terminal, `encrypt` asks for the password twice so a typo cannot lock you out of your own file.

**Atomic Writes**: Output is written to a temporary file in the destination directory and renamed into place, so a failed run never truncates or half-writes an existing file.

**Password Input**: Password is read with terminal echo disabled, so nothing appears on screen as you type, protecting against shoulder surfing and terminal history.

### File Format

```
V2: [1 byte: version=2] [16 bytes: salt] [12 bytes: nonce] [rest: encrypted data]
V1: [1 byte: version=1] [12 bytes: nonce] [rest: encrypted data]
```

In V2 the version and salt are authenticated as GCM additional data, so tampering with the header makes decryption fail.

The version byte allows Bitseal to automatically route decryption to the correct algorithm, even as new versions are added.

## Why Version Your Encryption?

The OpenSSL problem: In 2023, OpenSSL changed its default digest from MD5 to SHA-256 for `enc` command. If you had encrypted files with the old version, you couldn't decrypt them anymore without specifying legacy parameters.

Bitseal solves this by embedding the version number in every encrypted file. When you decrypt, it automatically detects which algorithm was used and applies it, no matter how many new versions have been released.

## Architecture

The codebase is organized for easy maintenance and extension:

- **main.go**: CLI entry point and command routing
- **crypto.go**: Core cryptography with `CipherVersion` interface
- **cipher_manager.go**: Version detection and file I/O operations
- **password.go**: Secure password input handling

### Adding a New Cipher Version

1. Create a new cipher implementation in `crypto.go`:
```go
type CipherV3 struct {
    version byte
    // ... new fields
}

func (c *CipherV3) Version() byte { return 3 }
func (c *CipherV3) Encrypt(plaintext, password []byte) ([]byte, error) { /* ... */ }
func (c *CipherV3) Decrypt(ciphertext, password []byte) ([]byte, error) { /* ... */ }
```

2. Register it in `cipher_manager.go`:
```go
ciphers: map[byte]CipherVersion{
    1: NewCipherV1(),
    2: NewCipherV2(),
    3: NewCipherV3(),  // New!
}
```

3. Set `CurrentVersion` in `cipher_manager.go` to `3` so new files use it, and add a golden vector for the new version in `crypto_test.go`.

That's it! Files encrypted with older versions will still decrypt automatically.

## Security Considerations

- **Password Strength**: Use strong passwords (16+ characters with mixed case, numbers, symbols). Weak passwords are the weakest link.
- **Salt**: V2 uses a random per-file salt stored in the header. V1 files use a static salt; re-encrypt them with the current version to upgrade.
- **File Permissions**: Output files are created with 0600 permissions (read/write only by owner).
- **No Authentication**: The tool encrypts files but doesn't sign them. For authentication, consider using GPG signatures alongside encrypted files.

## Examples

### Encrypt sensitive notes
```bash
./bitseal encrypt -file notes.txt
# Enter password when prompted
```

### Batch encryption
```bash
for file in *.doc; do
  ./bitseal encrypt -file "$file"
done
```

### Backup and encrypt
```bash
tar czf backup.tar.gz /path/to/data
./bitseal encrypt -file backup.tar.gz -out backup.tar.gz.enc
rm backup.tar.gz
```

## Troubleshooting

**"decryption failed (wrong password or corrupted file)"**
- Check that you entered the correct password
- Verify the file hasn't been corrupted or tampered with
- Ensure you're using the correct version of Bitseal

**"cannot infer output path: input does not end in .enc, use -out"**
- Pass `-out <path>` to say where the decrypted file should go

**"output path must differ from input path"**
- Choose a different `-out`; Bitseal never writes over the file it is reading

**"passwords do not match"**
- The two prompts on `encrypt` differed; run the command again

**"unsupported encryption version"**
- Your encrypted file uses a newer encryption version than your Bitseal build
- Update Bitseal to the latest version

**Password input not hidden**
- This can happen with some terminal emulators or when input is redirected
- Bitseal falls back to plain input in these cases for compatibility

## Development

### Running tests
```bash
make test         # all tests (unit + end-to-end, builds the binary)
make test-short   # skips the large-file cases
make test-race    # with the race detector (slow: Argon2 uses 64 MiB per key)
```

The suite covers both cipher versions (round trips, wrong passwords, tampering, truncation, golden vectors for on-disk compatibility), file operations (output naming, permissions, atomic writes, refusal to overwrite the input) and the compiled CLI end to end.

### Building
```bash
go build -o bitseal
```

### Formatting
```bash
go fmt ./...
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is provided as-is. While it uses well-established cryptographic algorithms, no security tool is perfect. For highly sensitive data, consider using established tools like GPG or encrypting filesystems. Always test on non-critical data first and maintain secure backups of your passwords.
