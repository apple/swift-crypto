# ``Crypto``

A cryptography library for Swift.

## Overview

Swift Crypto provides a Swift library for common cryptographic operations. It is available as a Swift package and provides two main libraries:

* `Crypto` - an open-source implementation of a substantial portion of the API of [Apple CryptoKit](https://developer.apple.com/documentation/cryptokit) suitable for use on Linux platforms. It enables cross-platform or server applications with the advantages of CryptoKit.
* `CryptoExtras` - a collection of additional cryptographic primitives and utilities that are not part of CryptoKit but useful in a server environment.

Swift Crypto is built on top of [BoringSSL](https://boringssl.googlesource.com/boringssl/), Google's fork of OpenSSL. The current features of Swift Crypto cover key exchange, key derivation, encryption and decryption, hashing, message authentication, and more.