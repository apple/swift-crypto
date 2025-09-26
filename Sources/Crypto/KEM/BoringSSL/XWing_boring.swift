//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct OpenSSLXWingPublicKeyImpl: Sendable {
    private var publicKeyBytes: Data

    fileprivate init(publicKeyBytes: Data) {
        self.publicKeyBytes = publicKeyBytes
    }

    init<D: ContiguousBytes>(rawRepresentation: D) throws {
        self.publicKeyBytes = try rawRepresentation.withUnsafeBytes {
            guard $0.count == XWING_PUBLIC_KEY_BYTES else {
                throw CryptoKitError.incorrectKeySize
            }
            return Data($0)
        }
    }

    var rawRepresentation: Data {
        self.publicKeyBytes
    }

    func encapsulate() throws -> KEM.EncapsulationResult {
        try self.encapsulateWithOptionalEntropy(entropy: nil)
    }

    func encapsulateWithOptionalEntropy(entropy: [UInt8]?) throws -> KEM.EncapsulationResult {
        let (sharedSecret, encapsulatedSecret) = try self.publicKeyBytes.withUnsafeBytes { publicKeyBuffer in
            try withUnsafeTemporaryAllocation(byteCount: Int(XWING_CIPHERTEXT_BYTES), alignment: 1) {
                ciphertextBuffer in
                let sharedSecret = try SymmetricKey(unsafeUninitializedCapacity: Int(XWING_SHARED_SECRET_BYTES)) {
                    sharedSecretBuffer,
                    count in
                    let rc: CInt

                    if let entropy {
                        rc = CCryptoBoringSSL_XWING_encap_external_entropy(
                            ciphertextBuffer.baseAddress,
                            sharedSecretBuffer.baseAddress,
                            publicKeyBuffer.baseAddress,
                            entropy
                        )
                    } else {
                        rc = CCryptoBoringSSL_XWING_encap(
                            ciphertextBuffer.baseAddress,
                            sharedSecretBuffer.baseAddress,
                            publicKeyBuffer.baseAddress
                        )
                    }
                    guard rc == 1 else {
                        throw CryptoKitError.internalBoringSSLError()
                    }
                    count = Int(XWING_SHARED_SECRET_BYTES)
                }
                let encapsulatedSecret = Data(ciphertextBuffer)
                return (sharedSecret, encapsulatedSecret)
            }
        }

        return .init(sharedSecret: sharedSecret, encapsulated: encapsulatedSecret)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct OpenSSLXWingPrivateKeyImpl: Sendable {
    private var backing: Backing

    var seedRepresentation: Data {
        self.backing.seedRepresentation
    }

    var integrityCheckedRepresentation: Data {
        self.backing.integrityCheckedRepresentation
    }

    init<D: ContiguousBytes>(bytes: D) throws {
        self.backing = try .init(bytes: bytes)
    }

    init<D: DataProtocol>(seedRepresentation: D, publicKeyHash: SHA3_256Digest?) throws {
        self.backing = try .init(seedRepresentation: seedRepresentation, publicKeyHash: publicKeyHash)
    }

    private init(_ backing: Backing) {
        self.backing = backing
    }

    var dataRepresentation: Data {
        self.backing.dataRepresentation
    }

    static func generate() throws -> Self {
        try Self(.generate())
    }

    func decapsulate(_ encapsulated: Data) throws -> SymmetricKey {
        try self.backing.decapsulate(encapsulated)
    }

    var publicKey: OpenSSLXWingPublicKeyImpl {
        OpenSSLXWingPublicKeyImpl(publicKeyBytes: self.backing.publicKey)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OpenSSLXWingPrivateKeyImpl {
    final class Backing: @unchecked Sendable {
        private var privateKey: XWING_private_key

        init(privateKey: XWING_private_key) {
            self.privateKey = privateKey
        }

        init() throws {
            self.privateKey = .init()
            try withUnsafeTemporaryAllocation(byteCount: Int(XWING_PUBLIC_KEY_BYTES), alignment: 1) {
                let rc = CCryptoBoringSSL_XWING_generate_key($0.baseAddress, &self.privateKey)
                if rc != 1 {
                    throw CryptoKitError.internalBoringSSLError()
                }
            }
        }

        init<D: ContiguousBytes>(bytes: D) throws {
            self.privateKey = .init()

            // The first bytes are the private key (in "seed representation"), the latter bytes are the public key.
            try bytes.withUnsafeBytes { ptr in
                guard ptr.count == Int(XWING_PRIVATE_KEY_BYTES) + Int(XWING_PUBLIC_KEY_BYTES) else {
                    throw CryptoKitError.incorrectKeySize
                }
                let privateKeyBytes = UnsafeRawBufferPointer(rebasing: ptr.prefix(Int(XWING_PRIVATE_KEY_BYTES)))
                let publicKeyBytes = UnsafeRawBufferPointer(rebasing: ptr.suffix(Int(XWING_PUBLIC_KEY_BYTES)))

                var cbs = CBS()
                CCryptoBoringSSL_CBS_init(&cbs, privateKeyBytes.baseAddress, privateKeyBytes.count)

                let rc = CCryptoBoringSSL_XWING_parse_private_key(&self.privateKey, &cbs)
                guard rc == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }

                // Matching CryptoKit, we only care that this _is_ a public key, not that it matches.
                let _ = try OpenSSLXWingPublicKeyImpl(rawRepresentation: publicKeyBytes)
            }
        }

        init<D: DataProtocol>(seedRepresentation: D, publicKeyHash: SHA3_256Digest?) throws {
            self.privateKey = .init()

            let seedRepresentation: ContiguousBytes =
                seedRepresentation.regions.count == 1 ? seedRepresentation.regions.first! : Array(seedRepresentation)

            try seedRepresentation.withUnsafeBytes { privateKeyBytes in
                guard privateKeyBytes.count == Int(XWING_PRIVATE_KEY_BYTES) else {
                    throw CryptoKitError.incorrectKeySize
                }

                var cbs = CBS()
                CCryptoBoringSSL_CBS_init(&cbs, privateKeyBytes.baseAddress, privateKeyBytes.count)

                let rc = CCryptoBoringSSL_XWING_parse_private_key(&self.privateKey, &cbs)
                guard rc == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }
            }

            if let publicKeyHash, publicKeyHash != self.publicKeyDigest {
                throw KEM.Errors.publicKeyMismatchDuringInitialization
            }
        }

        var seedRepresentation: Data {
            withUnsafeTemporaryAllocation(byteCount: Int(XWING_PRIVATE_KEY_BYTES), alignment: 1) {
                var cbb = CBB()
                CCryptoBoringSSL_CBB_init_fixed(&cbb, $0.baseAddress, $0.count)
                let rc = CCryptoBoringSSL_XWING_marshal_private_key(&cbb, &self.privateKey)
                precondition(rc == 1)
                return Data($0.prefix(CCryptoBoringSSL_CBB_len(&cbb)))
            }
        }

        var integrityCheckedRepresentation: Data {
            var representation = self.seedRepresentation
            self.publicKeyDigest.withUnsafeBytes {
                representation.append(contentsOf: $0)
            }
            return representation
        }

        var dataRepresentation: Data {
            self.seedRepresentation + self.publicKey
        }

        var publicKey: Data {
            withUnsafeTemporaryAllocation(byteCount: Int(XWING_PUBLIC_KEY_BYTES), alignment: 1) {
                let rc = CCryptoBoringSSL_XWING_public_from_private($0.baseAddress, &self.privateKey)
                precondition(rc == 1)
                return Data($0)
            }
        }

        private var publicKeyDigest: SHA3_256Digest {
            withUnsafeTemporaryAllocation(byteCount: Int(XWING_PUBLIC_KEY_BYTES), alignment: 1) {
                let rc = CCryptoBoringSSL_XWING_public_from_private($0.baseAddress, &self.privateKey)
                precondition(rc == 1)
                return SHA3_256.hash(bufferPointer: UnsafeRawBufferPointer($0))
            }
        }

        static func generate() throws -> Self {
            try Self()
        }

        func decapsulate(_ encapsulated: Data) throws -> SymmetricKey {
            try SymmetricKey(unsafeUninitializedCapacity: Int(XWING_SHARED_SECRET_BYTES)) { sharedSecretBytes, count in
                try encapsulated.withUnsafeBytes { encapsulatedSecretBytes in
                    let rc = CCryptoBoringSSL_XWING_decap(
                        sharedSecretBytes.baseAddress,
                        encapsulatedSecretBytes.baseAddress,
                        &self.privateKey
                    )
                    guard rc == 1 else {
                        throw CryptoKitError.internalBoringSSLError()
                    }
                    count = Int(XWING_SHARED_SECRET_BYTES)
                }
            }
        }
    }
}

#endif  // CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
