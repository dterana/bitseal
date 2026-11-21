# Using Casemate with tar

`casemate encrypt` on a directory writes an uncompressed tar archive. When you want compression, a different archive tool, or tar options such as excludes, run `tar` yourself and pipe it through Casemate. The file format is the same either way.

The password cannot come from stdin when the data does, so these examples use `-password-file`. `-password-env` and `-password-fd` work too.

## Back up a directory

```bash
tar czf - ./project | casemate encrypt -password-file pw -file - -out project.tar.gz.enc
```

`-file -` reads the archive from stdin and `-out` is required, because there is no file name to derive one from. Progress goes to stderr, so the pipe stays clean.

## Restore it

```bash
casemate decrypt -password-file pw -file project.tar.gz.enc -out - | tar xzf -
```

Two things to know:

- `decrypt -out -` holds the plaintext back until the whole file has authenticated, then writes it. A corrupt or tampered file prints nothing, so `tar` never sees bad data. The cost is that the plaintext is buffered in memory, so for very large archives decrypt to a file first and run `tar` on that file.
- `tar` unpacks whatever the archive says, including absolute paths and links, depending on your `tar`. Only unpack archives you made. For archives you did not make, use `casemate decrypt -extract` on a `.tar.enc` made by `casemate encrypt <dir>`, which refuses paths that escape the target, links and special files.

## Look inside without extracting

```bash
casemate decrypt -password-file pw -file project.tar.gz.enc -out - | tar tzf -
```

## Exclude files, or pick a compressor

```bash
tar czf - --exclude node_modules --exclude .git ./project \
  | casemate encrypt -password-file pw -file - -out project.tar.gz.enc

tar cf - ./project | zstd -T0 | casemate encrypt -password-file pw -file - -out project.tar.zst.enc
casemate decrypt -password-file pw -file project.tar.zst.enc -out - | zstd -d | tar xf -
```

## Checking that it worked

Exit codes are real, but a shell pipeline reports only the last command's status unless you ask for more:

```bash
set -o pipefail            # bash and zsh: fail if any stage fails
tar czf - ./project | casemate encrypt -password-file pw -file - -out project.tar.gz.enc
```

Without `pipefail`, a failing `tar` can still leave a valid encrypted file that holds a truncated archive. After a backup, `casemate info project.tar.gz.enc` confirms the file is a Casemate file, and a test restore into a scratch directory confirms the content.

## Which one should I use?

| | `casemate encrypt <dir>` | `tar ... \| casemate encrypt -file -` |
|---|---|---|
| Compression and tar options | no | yes |
| Restore | `decrypt -extract`, hardened against hostile archives | `tar` of your choice |
| Symbolic links | refused, with the path named | whatever `tar` stores |
| Memory on restore | bounded | whole plaintext buffered with `-out -` |
