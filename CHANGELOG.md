# Changelog

All notable changes to Casemate. The format follows [Keep a Changelog](https://keepachangelog.com), and the project follows [Semantic Versioning](https://semver.org) with the usual pre-1.0 caveat: a minor version may change behaviour, never the ability to read files written by an earlier version.

## [0.7.0] - 2026-11-20

### Added
- `-strict` for `encrypt`, `decrypt` and `rekey`: a password file that other users can read, and a new password under 12 characters, become errors instead of warnings. Decrypting never fails on length.
- A release smoke test that downloads each published release and checks the checksum, the build attestation, the version and a folder round trip on Linux amd64, Linux arm64 and macOS arm64.

### Changed
- Releases are no longer marked as pre-releases.
- CI and release jobs have timeouts so a hung runner fails fast.

## [0.6.1] - 2026-11-17

### Fixed
- The release now fails when the tag does not match the version in the code.

### Changed
- `v0.6.0` is retracted in `go.mod`; use `v0.6.1` or later.

## Earlier versions

The history was republished from a clean start at `v0.6.0`, which is retracted along with `v0.1.0` to `v0.5.0`. Features that shipped before: AES-256-GCM chunked encryption with Argon2id (file format v2, still reading v1), streaming with bounded memory, directory archives (`encrypt` a folder, `decrypt -extract`), `keygen`, `-password-fd`, `rekey`, `info`, and Homebrew, `.deb` and `.rpm` packaging.

[0.7.0]: https://github.com/dterana/casemate/releases/tag/v0.7.0
[0.6.1]: https://github.com/dterana/casemate/releases/tag/v0.6.1
