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

extension Curve25519.KeyAgreement {
    @usableFromInline
    static let keySizeBytes = 32

    @usableFromInline
    struct OpenSSLCurve25519PublicKeyImpl {
        @usableFromInline
        var keyBytes: [UInt8]

        @inlinable
        init<D: ContiguousBytes>(rawRepresentation: D) throws {
            self.keyBytes = try rawRepresentation.withUnsafeBytes { dataPtr in
                guard dataPtr.count == Curve25519.KeyAgreement.keySizeBytes else {
                    throw CryptoKitError.incorrectKeySize
                }

                return Array(dataPtr)
            }
        }

        @usableFromInline
        init(_ keyBytes: [UInt8]) {
            self.keyBytes = keyBytes
        }

        @usableFromInline
        var rawRepresentation: Data {
            return Data(self.keyBytes)
        }
    }

    @usableFromInline
    struct OpenSSLCurve25519PrivateKeyImpl {
        var key: SecureBytes

        @usableFromInline
        var publicKey: OpenSSLCurve25519PublicKeyImpl

        init() {
            var publicKey = Array(repeating: UInt8(0), count: Curve25519.KeyAgreement.keySizeBytes)

            self.key = SecureBytes(unsafeUninitializedCapacity: Curve25519.KeyAgreement.keySizeBytes) { privateKeyBytes, privateKeySize in
                publicKey.withUnsafeMutableBytes { publicKeyBytes in
                    precondition(publicKeyBytes.count >= Curve25519.KeyAgreement.keySizeBytes)
                    precondition(privateKeyBytes.count >= Curve25519.KeyAgreement.keySizeBytes)
                    CCryptoBoringSSLShims_X25519_keypair(publicKeyBytes.baseAddress, privateKeyBytes.baseAddress)
                }
                privateKeySize = Curve25519.KeyAgreement.keySizeBytes // We always use the whole thing.
            }
            self.publicKey = .init(publicKey)

            // BoringSSL performs an "anti-mask" of the private key. That's well-motivated, but corecrypto doesn't
            // and we'd like to behave the same way. Undo the private key anti-mask.
            let firstByteIndex = self.key.startIndex
            let lastByteIndex = self.key.index(before: self.key.endIndex)
            self.key[firstByteIndex] &= 248
            self.key[lastByteIndex] &= 127
            self.key[lastByteIndex] |= 64
        }

        init<D: ContiguousBytes>(rawRepresentation: D) throws {
            let publicBytes: [UInt8] = try rawRepresentation.withUnsafeBytes { privatePointer in
                try OpenSSLCurve25519PrivateKeyImpl.validateX25519PrivateKeyData(rawRepresentation: privatePointer)

                return Array(unsafeUninitializedCapacity: Curve25519.KeyAgreement.keySizeBytes) { publicKeyBytes, publicKeySize in
                    precondition(publicKeyBytes.count >= Curve25519.KeyAgreement.keySizeBytes)
                    CCryptoBoringSSLShims_X25519_public_from_private(publicKeyBytes.baseAddress, privatePointer.baseAddress)
                    publicKeySize = Curve25519.KeyAgreement.keySizeBytes // We always use the whole thing.
                }
            }

            self.key = SecureBytes(bytes: rawRepresentation)
            self.publicKey = .init(publicBytes)
        }

        @usableFromInline
        func sharedSecretFromKeyAgreement(with publicKeyShare: OpenSSLCurve25519PublicKeyImpl) throws -> SharedSecret {
            let sharedSecret = SecureBytes(unsafeUninitializedCapacity: Curve25519.KeyAgreement.keySizeBytes) { secretPointer, secretSize in
                self.key.withUnsafeBytes { privateKeyPointer in
                    // We precondition on all of these sizes because bounds checking is cool.
                    // These are fatal instead of guards because we allocated the secret (so it must be right),
                    // we either allocated the private key or validated it on construction (so it must be right),
                    // and we validated the public key on construction (so it must be right).
                    precondition(secretPointer.count == Curve25519.KeyAgreement.keySizeBytes)
                    precondition(privateKeyPointer.count == Curve25519.KeyAgreement.keySizeBytes)
                    precondition(publicKeyShare.keyBytes.count == Curve25519.KeyAgreement.keySizeBytes)

                    // We don't check the return code here. This return code only validates that the generated secret is not the weak all-zero
                    // secret (it is not possible for BoringSSL's X25519 implementation to fail, which is nice). There is currently what I would
                    // politely describe as a "lack of consensus" as to whether crypto libraries should reject this secret. CryptoKit on Apple
                    // platforms currently does not, so for the sake of conformance with our peer implementation I will also refuse to check it.
                    // We may elect to revisit this decision if the security best-practice thinking changes.
                    CCryptoBoringSSLShims_X25519(secretPointer.baseAddress, privateKeyPointer.baseAddress, publicKeyShare.keyBytes)
                }

                secretSize = Curve25519.KeyAgreement.keySizeBytes // We always use all of it.
            }

            return SharedSecret(ss: sharedSecret)
        }

        @usableFromInline
        var rawRepresentation: Data {
            return Data(self.key)
        }

        /// Validates whether the passed x25519 key representation is valid.
        /// - Parameter rawRepresentation: The provided key representation. Expected to be a valid 32-bytes private key.
        static func validateX25519PrivateKeyData(rawRepresentation: UnsafeRawBufferPointer) throws {
            guard rawRepresentation.count == 32 else {
                throw CryptoKitError.incorrectKeySize
            }
        }
    }
}
#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
