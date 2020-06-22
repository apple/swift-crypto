//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
import Foundation

// For signing and verifying, we use BoringSSL's Ed25519, not the X25519 stuff.
extension Curve25519.Signing {
    @usableFromInline
    struct OpenSSLCurve25519PrivateKeyImpl {
        /* private but @usableFromInline */ var _privateKey: SecureBytes
        /* private but @usableFromInline */ @usableFromInline var _publicKey: [UInt8]

        @usableFromInline
        init() {
            // BoringSSL's Ed25519 implementation stores the private key concatenated with the public key, so we do
            // as well. We also store the public key because it makes our lives easier.
            var publicKey = Array(repeating: UInt8(0), count: 32)
            let privateKey = SecureBytes(unsafeUninitializedCapacity: 64) { privateKeyPtr, privateKeyBytes in
                privateKeyBytes = 64
                publicKey.withUnsafeMutableBytes { publicKeyPtr in
                    CCryptoBoringSSLShims_ED25519_keypair(publicKeyPtr.baseAddress, privateKeyPtr.baseAddress)
                }
            }

            self._privateKey = privateKey
            self._publicKey = publicKey
        }

        @usableFromInline
        var publicKey: Curve25519.Signing.OpenSSLCurve25519PublicKeyImpl {
            return OpenSSLCurve25519PublicKeyImpl(self._publicKey)
        }

        var key: SecureBytes {
            return self._privateKey
        }

        init<D: ContiguousBytes>(rawRepresentation data: D) throws {
            // What this calls "rawRepresentation" BoringSSL calls the "seed". Otherwise, this is
            // the same as the above initializer.
            var publicKey = Array(repeating: UInt8(0), count: 32)
            let privateKey: SecureBytes = try data.withUnsafeBytes { seedPtr in
                guard seedPtr.count == 32 else {
                    throw CryptoKitError.incorrectKeySize
                }

                let privateKey = SecureBytes(unsafeUninitializedCapacity: 64) { privateKeyPtr, privateKeyBytes in
                    privateKeyBytes = 64
                    publicKey.withUnsafeMutableBytes { publicKeyPtr in
                        CCryptoBoringSSLShims_ED25519_keypair_from_seed(publicKeyPtr.baseAddress, privateKeyPtr.baseAddress, seedPtr.baseAddress)
                    }
                }

                return privateKey
            }

            self._privateKey = privateKey
            self._publicKey = publicKey
        }

        @usableFromInline
        var rawRepresentation: Data {
            // The "rawRepresentation" is what BoringSSL calls the "seed", and it's the first 32 bytes of our key.
            return Data(self._privateKey.prefix(32))
        }
    }

    @usableFromInline
    struct OpenSSLCurve25519PublicKeyImpl {
        @usableFromInline
        var keyBytes: [UInt8]

        @inlinable
        init<D: ContiguousBytes>(rawRepresentation: D) throws {
            self.keyBytes = try rawRepresentation.withUnsafeBytes { keyBytesPtr in
                guard keyBytesPtr.count == 32 else {
                    throw CryptoKitError.incorrectKeySize
                }
                return Array(keyBytesPtr)
            }
        }

        init(_ keyBytes: [UInt8]) {
            precondition(keyBytes.count == 32)
            self.keyBytes = keyBytes
        }

        var rawRepresentation: Data {
            return Data(self.keyBytes)
        }
    }
}
#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
