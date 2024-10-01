//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import Foundation

@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims

/// Types associated with the ML-DSA-65 algorithm
@_documentation(visibility: public)
public enum MLDSA {}

extension MLDSA {
    /// A ML-DSA-65 private key.
    public struct PrivateKey: Sendable {
        fileprivate let pointer: UnsafeMutablePointer<MLDSA65_private_key>

        /// Initialize a ML-DSA-65 private key from a random seed.
        /// 
        /// - Throws: ``CryptoMLDSAError/keyGenerationFailure`` if the key could not be generated.
        public init() throws {
            self.pointer = UnsafeMutablePointer<MLDSA65_private_key>.allocate(capacity: 1)

            let publicKeyPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: MLDSA.PublicKey.bytesCount)
            let seedPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: MLDSA.seedSizeInBytes)
            defer {
                publicKeyPtr.deallocate()
                seedPtr.deallocate()
            }

            guard CCryptoBoringSSL_MLDSA65_generate_key(
                publicKeyPtr,
                seedPtr,
                self.pointer
            ) == 1 else {
                throw CryptoMLDSAError.keyGenerationFailure
            }
        }

        /// Initialize a ML-DSA-65 private key from a seed.
        /// 
        /// The seed must be at least 32 bytes long.
        /// Any additional bytes in the seed are ignored.
        /// 
        /// - Parameter seed: The seed to use to generate the private key.
        /// 
        /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not at least 32 bytes long or ``CryptoMLDSAError/keyGenerationFailure`` if the key could not be generated.
        public init(from seed: some DataProtocol) throws {
            guard seed.count >= MLDSA.seedSizeInBytes else {
                throw CryptoKitError.incorrectKeySize
            }

            let seedPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: MLDSA.seedSizeInBytes)
            seedPtr.initialize(from: seed.regions.flatMap { $0 }, count: MLDSA.seedSizeInBytes)
            defer { seedPtr.deallocate() }

            self.pointer = UnsafeMutablePointer<MLDSA65_private_key>.allocate(capacity: 1)

            guard CCryptoBoringSSL_MLDSA65_private_key_from_seed(
                self.pointer,
                seedPtr,
                MLDSA.seedSizeInBytes
            ) == 1 else {
                throw CryptoMLDSAError.keyGenerationFailure
            }
        }

        /// Initialize a ML-DSA-65 private key from a DER representation.
        /// 
        /// - Parameter derRepresentation: The DER representation of the private key.
        /// 
        /// - Throws: `CryptoKitError.incorrectKeySize` if the DER representation is not the correct size or ``CryptoMLDSAError/keyGenerationFailure`` if the key could not be generated.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            guard derRepresentation.count == MLDSA.PrivateKey.bytesCount else {
                throw CryptoKitError.incorrectKeySize
            }

            self.pointer = UnsafeMutablePointer<MLDSA65_private_key>.allocate(capacity: 1)

            let cbsPointer = UnsafeMutablePointer<CBS>.allocate(capacity: 1)
            defer { cbsPointer.deallocate() }
            derRepresentation.regions.flatMap { $0 }.withUnsafeBufferPointer { buffer in
                cbsPointer.pointee = CBS(data: buffer.baseAddress, len: buffer.count)
            }

            guard CCryptoBoringSSL_MLDSA65_parse_private_key(self.pointer, cbsPointer) == 1 else {
                throw CryptoMLDSAError.keyGenerationFailure
            }
        }

        /// Initialize a ML-DSA-65 private key from a PEM representation.
        /// 
        /// - Parameter pemRepresentation: The PEM representation of the private key.
        public init(pemRepresentation: String) throws {
            let document = try ASN1.PEMDocument(pemString: pemRepresentation)
            self = try .init(derRepresentation: document.derBytes)
        }

        /// The public key associated with this private key.
        public var publicKey: PublicKey {
            get throws {
                try PublicKey(privateKey: self)
            }
        }

        /// Generate a signature for the given data.
        /// 
        /// - Parameters: 
        ///   - data: The message to sign.
        ///   - context: The context to use for the signature.
        /// 
        /// - Returns: The signature of the message.
        public func signature<D: DataProtocol>(for data: D, context: [UInt8]? = nil) throws -> Signature {
            let output = try Array<UInt8>(unsafeUninitializedCapacity: Signature.bytesCount) { bufferPtr, length in
                let result = data.regions.first!.withUnsafeBytes { dataPtr in
                    let contextPointer = context?.withUnsafeBufferPointer { $0.baseAddress }
                    let contextLength = context?.count ?? 0

                    return CCryptoBoringSSL_MLDSA65_sign(
                        bufferPtr.baseAddress,
                        self.pointer,
                        dataPtr.baseAddress,
                        dataPtr.count,
                        contextPointer,
                        contextLength
                    )
                }

                guard result == 1 else {
                    throw CryptoMLDSAError.signatureGenerationFailure
                }

                length = Signature.bytesCount
            }
            return Signature(signatureBytes: output)
        }

        /// The size of the private key in bytes.
        public static let bytesCount = 4032
    }
}

extension MLDSA {
    /// A ML-DSA-65 public key.
    public struct PublicKey: Sendable {
        private let pointer: UnsafeMutablePointer<MLDSA65_public_key>

        fileprivate init(privateKey: PrivateKey) throws {
            self.pointer = UnsafeMutablePointer<MLDSA65_public_key>.allocate(capacity: 1)

            guard CCryptoBoringSSL_MLDSA65_public_from_private(
                self.pointer,
                privateKey.pointer
            ) == 1 else {
                throw CryptoMLDSAError.keyGenerationFailure
            }
        }

        /// Initialize a ML-DSA-65 public key from a seed.
        /// 
        /// The seed must be at least 32 bytes long.
        /// Any additional bytes in the seed are ignored.
        /// 
        /// - Parameter seed: The seed to use to generate the public key.
        public init(from seed: some DataProtocol) throws {
            try self.init(privateKey: PrivateKey(from: seed))
        }

        /// Initialize a ML-DSA-65 public key from a DER representation.
        /// 
        /// - Parameter derRepresentation: The DER representation of the public key.
        /// 
        /// - Throws: `CryptoKitError.incorrectKeySize` if the DER representation is not the correct size or ``CryptoMLDSAError/keyGenerationFailure`` if the key could not be generated.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            guard derRepresentation.count == MLDSA.PublicKey.bytesCount else {
                throw CryptoKitError.incorrectKeySize
            }

            self.pointer = UnsafeMutablePointer<MLDSA65_public_key>.allocate(capacity: 1)

            let cbsPointer = UnsafeMutablePointer<CBS>.allocate(capacity: 1)
            defer { cbsPointer.deallocate() }
            derRepresentation.regions.flatMap { $0 }.withUnsafeBufferPointer { buffer in
                cbsPointer.pointee = CBS(data: buffer.baseAddress, len: buffer.count)
            }

            guard CCryptoBoringSSL_MLDSA65_parse_public_key(self.pointer, cbsPointer) == 1 else {
                throw CryptoMLDSAError.keyGenerationFailure
            }
        }

        /// Initialize a ML-DSA-65 public key from a PEM representation.
        /// 
        /// - Parameter pemRepresentation: The PEM representation of the public key.
        public init(pemRepresentation: String) throws {
            let document = try ASN1.PEMDocument(pemString: pemRepresentation)
            self = try .init(derRepresentation: document.derBytes)
        }

        /// The DER representation of the public key.
        public var derRepresentation: Data {
            get throws {
                let cbbPointer = UnsafeMutablePointer<CBB>.allocate(capacity: 1)
                defer { cbbPointer.deallocate() }
                
                guard CCryptoBoringSSL_CBB_init(cbbPointer, MLDSA.PublicKey.bytesCount) == 1 else {
                    CCryptoBoringSSL_CBB_cleanup(cbbPointer)
                    throw CryptoMLDSAError.keyGenerationFailure
                }

                guard CCryptoBoringSSL_MLDSA65_marshal_public_key(cbbPointer, self.pointer) == 1 else {
                    CCryptoBoringSSL_CBB_cleanup(cbbPointer)
                    throw CryptoMLDSAError.keyGenerationFailure
                }

                guard let data = CCryptoBoringSSL_CBB_data(cbbPointer) else {
                    CCryptoBoringSSL_CBB_cleanup(cbbPointer)
                    throw CryptoMLDSAError.keyGenerationFailure
                }
                return Data(bytes: data, count: CCryptoBoringSSL_CBB_len(cbbPointer))
            }
        }

        /// The PEM representation of the public key.
        public var pemRepresentation: String {
            get throws {
                ASN1.PEMDocument(type: MLDSA.PublicKeyType, derBytes: try self.derRepresentation).pemString
            }
        }

        /// Verify a signature for the given data.
        /// 
        /// - Parameters:
        ///   - signature: The signature to verify.
        ///   - data: The message to verify the signature against.
        ///   - context: The context to use for the signature verification.
        /// 
        /// - Returns: `true` if the signature is valid, `false` otherwise.
        public func isValidSignature<D: DataProtocol>(_ signature: Signature, for data: D, context: [UInt8]? = nil) -> Bool {
            return signature.withUnsafeBytes { signaturePtr in
                let rc: CInt = data.regions.first!.withUnsafeBytes { dataPtr in
                    let contextPointer = context?.withUnsafeBufferPointer { $0.baseAddress }
                    let contextLength = context?.count ?? 0

                    return CCryptoBoringSSL_MLDSA65_verify(
                        self.pointer,
                        signaturePtr.baseAddress,
                        signaturePtr.count,
                        dataPtr.baseAddress,
                        dataPtr.count,
                        contextPointer,
                        contextLength
                    )
                }
                return rc == 1
            }
        }

        /// The size of the public key in bytes.
        public static let bytesCount = 1952
    }
}

extension MLDSA {
    /// A ML-DSA-65 signature.
    public struct Signature: Sendable, ContiguousBytes {
        /// The raw binary representation of the signature.
        public var rawRepresentation: Data

        /// Initialize a ML-DSA-65 signature from a raw representation.
        /// 
        /// - Parameter rawRepresentation: The signature bytes.
        public init<D: DataProtocol>(rawRepresentation: D) {
            self.rawRepresentation = Data(rawRepresentation)
        }

        /// Initialize a ML-DSA-65 signature from a raw representation.
        /// 
        /// - Parameter signatureBytes: The signature bytes.
        internal init(signatureBytes: [UInt8]) {
            self.rawRepresentation = Data(signatureBytes)
        }

        /// Access the signature bytes.
        /// 
        /// - Parameter body: The closure to execute with the signature bytes.
        /// 
        /// - Returns: The result of the closure.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }

        /// The size of the signature in bytes.
        public static let bytesCount = 3309
    }
}

extension MLDSA {
    /// The ASN.1 object identifiers for a private ML-DSA-65 key.
    static let KeyType = "PRIVATE KEY"
    
    /// The ASN.1 object identifiers for a public ML-DSA-65 key.
    static let PublicKeyType = "PUBLIC KEY"

    /// The size of the seed in bytes.
    public static let seedSizeInBytes = 32
}