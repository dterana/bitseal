# Bitseal file format

This document specifies the on-disk formats Bitseal reads and writes, and the
rules for changing them. It is written so that someone can implement a
compatible reader without reading the Go code.

All multi-byte integers are big endian. Byte offsets start at 0.

## Routing

The first byte of every file is the **format version**. A reader picks the
parser from that byte alone. A reader that does not know the version MUST
refuse the file (`unsupported encryption version`) and MUST NOT guess.

| Version | Status | Written by current builds | Read by current builds |
|:---:|---|:---:|:---:|
| 1 | legacy | no | yes |
| 2 | current | yes | yes |

## Version 1 (legacy)

```
offset  size  field
0       1     version = 0x01
1       12    nonce
13      n+16  AES-256-GCM ciphertext followed by the 16 byte tag
```

- Key: `PBKDF2-HMAC-SHA256(password, salt = "static-salt-v1", iterations = 100000, 32 bytes)`.
- No additional authenticated data. The version byte is therefore not
  authenticated; it is only used for routing.
- The whole file is one GCM message, so it must be read into memory.
- No key file support. The static salt is a known weakness; use `bitseal rekey`
  to upgrade V1 files.

## Version 2 (current)

### Header (35 bytes)

```
offset  size  field
0       1     version = 0x02
1       1     flags
2       1     chunk size exponent c (chunks hold 2^c bytes of data)
3       4     Argon2id time cost t
7       4     Argon2id memory cost m, in KiB
11      1     Argon2id parallelism p
12      16    salt (random per file)
28      7     nonce prefix (random per file)
```

Flags:

| Bit | Meaning |
|:---:|---|
| 0 | A key file is required to decrypt |
| 1 to 7 | Reserved. A reader MUST refuse a file with any of these set |

Limits applied when reading, so a hostile header cannot exhaust resources.
A reader MUST refuse values outside them:

| Field | Allowed |
|---|---|
| chunk size exponent | 4 to 24 |
| time cost t | 1 to 64 |
| parallelism p | 1 to 64 |
| memory cost m | at least 8 * p KiB, at most 1048576 KiB (1 GiB) |

### Key derivation

```
material = password                                   (no key file)
material = password || SHA-256(key file contents)     (flag bit 0 set)
key      = Argon2id(material, salt, t, m, p, 32 bytes)
```

The parameters come from the header, so a file always decrypts with the cost it
was written with, whatever the reader's current defaults are.

### Body

The body is a sequence of one or more chunks. Each chunk is
`AES-256-GCM(key, nonce, plaintext chunk, aad = header)` followed by its
16 byte tag, so it occupies up to `2^c + 16` bytes.

- Every chunk except the last holds exactly `2^c` bytes of plaintext.
- The last chunk holds 0 to `2^c` bytes. A file whose length is an exact
  multiple of `2^c` ends with a full-size last chunk. An empty plaintext is a
  single chunk of 0 bytes (just a tag).
- The nonce of chunk `i` (counting from 0) is 12 bytes:

  ```
  nonce prefix (7) || i as uint32 (4) || last (1)
  ```

  where `last` is `0x01` for the final chunk and `0x00` otherwise.
- The additional authenticated data of every chunk is the complete 35 byte
  header.

### Why this is safe

- The nonce encodes position and finality, so **reordering, duplicating or
  dropping** chunks, and **truncating** the file (including exactly at a chunk
  boundary), fail authentication.
- The header is authenticated by every chunk, so changing the KDF parameters,
  flags, chunk size or salt fails authentication.
- A reader MUST NOT release plaintext of a chunk before that chunk has
  authenticated. Bitseal additionally holds all output back when writing to
  stdout, and writes files through a temporary file that is only renamed into
  place after the last chunk authenticated.
- `counter` is a 32 bit value; a file cannot have more than 2^32 chunks.

## Rules for evolving the format

These rules are what "future proof" means for Bitseal.

1. **A released version is never removed or reinterpreted.** Every released
   version stays readable. New builds may stop *writing* an old version, never
   stop reading it. The golden vectors in `internal/testvectors` enforce this.
2. **Changing anything a reader must interpret differently needs a new version
   number.** That includes the cipher, the key derivation, the header layout,
   the nonce construction and the meaning of existing fields.
3. **Raising the cost needs no new version.** Argon2id parameters and the chunk
   size are stored in each file. Changing the defaults only affects new files,
   and `bitseal rekey` upgrades old ones.
4. **Optional features use flag bits.** A flag that changes how a file must be
   decrypted is safe to add without a new version, because readers refuse
   unknown flags instead of misreading the file. Reserve a flag only when old
   readers refusing the file is acceptable.
5. **Unknown means refuse.** Unknown versions and unknown flags are errors, not
   best-effort reads.
6. **Never regenerate a golden vector.** Add a new one. A vector that stops
   decrypting means the format changed incompatibly.
7. **Adding a version is mechanical.** Add one file that registers itself,
   document it here, add a golden vector, and raise `CurrentVersion`. The
   registry tests fail if any of these steps is forgotten.

## Test vectors

`internal/testvectors` contains encrypted files for every version and for the
V2 variants (default parameters, several chunks with parameters taken from the
header, an exact chunk boundary, a key file), together with the password, key
file and expected plaintext. They are the reference for anyone implementing a
compatible reader.
