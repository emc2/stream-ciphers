# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.3 (2019-10-23)
### Security
- Ensure block counter < MAX_BLOCKS ([#68])

[#68]: https://github.com/RustCrypto/stream-ciphers/pull/68

## 0.2.2 (2019-10-22)
### Added
- SSE2 accelerated implementation ([#61])

[#61]: https://github.com/RustCrypto/stream-ciphers/pull/61

## 0.2.1 (2019-08-19)
### Added
- Add `MAX_BLOCKS` and `BLOCK_SIZE` constants ([#47])

[#47]: https://github.com/RustCrypto/stream-ciphers/pull/47

## 0.2.0 (2019-08-18)
### Added
- `impl SyncStreamCipher` ([#39])
- `XChaCha20` ([#36])
- Support for 12-byte nonces ala RFC 8439 ([#19])

### Changed
- Refactor around a `ctr`-like type ([#44])
- Extract and encapsulate `Cipher` type ([#43])
- Switch tests to use `new_sync_test!` ([#42])
- Refactor into `ChaCha20` and `ChaCha20Legacy` ([#25])

### Fixed
- Fix `zeroize` cargo feature ([#21])
- Fix broken Cargo feature attributes ([#21])

[#44]: https://github.com/RustCrypto/stream-ciphers/pull/44
[#43]: https://github.com/RustCrypto/stream-ciphers/pull/43
[#42]: https://github.com/RustCrypto/stream-ciphers/pull/42
[#39]: https://github.com/RustCrypto/stream-ciphers/pull/39
[#36]: https://github.com/RustCrypto/stream-ciphers/pull/36
[#25]: https://github.com/RustCrypto/stream-ciphers/pull/25
[#21]: https://github.com/RustCrypto/stream-ciphers/pull/21
[#19]: https://github.com/RustCrypto/stream-ciphers/pull/19

## 0.1.0 (2019-06-24)

- Initial release
