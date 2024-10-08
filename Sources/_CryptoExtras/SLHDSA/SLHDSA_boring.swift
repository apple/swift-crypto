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

/// Types associated with the SLH-DSA-SHA2-128s algorithm
@_documentation(visibility: public)
public enum SLHDSA {}

extension SLHDSA {
    /// A SLH-DSA-SHA2-128s private key.
    public struct PrivateKey: Sendable {
        fileprivate let pointer: UnsafeMutablePointer<UInt8>
        
        public init() {
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SLHDSA.PrivateKey.bytesCount)

            let publicKeyPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: SLHDSA.PublicKey.bytesCount)
            defer { publicKeyPtr.deallocate() }

            CCryptoBoringSSL_SLHDSA_SHA2_128S_generate_key(publicKeyPtr, self.pointer)
        }

        public init(derRepresentation: some DataProtocol) throws {
            guard derRepresentation.count == SLHDSA.PrivateKey.bytesCount else {
                throw CryptoKitError.incorrectKeySize
            }

            var keyDest: [UInt8] = Array(repeating: 0, count: SLHDSA.PrivateKey.bytesCount)
            try keyDest.withUnsafeMutableBufferPointer { typedMemBuffer in
                guard derRepresentation.copyBytes(to: typedMemBuffer) == SLHDSA.PrivateKey.bytesCount else {
                    throw CryptoKitError.incorrectKeySize
                }
            }

            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SLHDSA.PrivateKey.bytesCount)
            self.pointer.initialize(from: keyDest, count: SLHDSA.PrivateKey.bytesCount)
        }
        
        public init(pemRepresentation: String) throws {
            let document = try ASN1.PEMDocument(pemString: pemRepresentation)
            self = try .init(derRepresentation: document.derBytes)
        }
        
        public var derRepresentation: Data {
            Data(UnsafeBufferPointer(start: self.pointer, count: SLHDSA.PrivateKey.bytesCount))
        }
        
        public var pemRepresentation: String {
            ASN1.PEMDocument(type: SLHDSA.keyType, derBytes: self.derRepresentation).pemString
        }

        fileprivate var bytes: [UInt8] {
            return Array(UnsafeBufferPointer(start: self.pointer, count: SLHDSA.PrivateKey.bytesCount))
        }

        public var publicKey: PublicKey {
            PublicKey(privateKey: self)
        }

        public func signature(for data: some DataProtocol, context: [UInt8]? = nil) throws -> Signature {
            let output = try Array<UInt8>(unsafeUninitializedCapacity: Signature.bytesCount) { bufferPtr, length in
                let result = data.regions.first!.withUnsafeBytes { dataPtr in
                    if let context {
                        context.withUnsafeBytes { contextPtr in
                            CCryptoBoringSSL_SLHDSA_SHA2_128S_sign(
                                bufferPtr.baseAddress,
                                self.pointer,
                                dataPtr.baseAddress,
                                dataPtr.count,
                                contextPtr.baseAddress,
                                contextPtr.count
                            )
                        }
                    } else {
                        CCryptoBoringSSL_SLHDSA_SHA2_128S_sign(
                            bufferPtr.baseAddress,
                            self.pointer,
                            dataPtr.baseAddress,
                            dataPtr.count,
                            nil,
                            0
                        )
                    }
                }

                guard result == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }

                length = Signature.bytesCount
            }
            return Signature(signatureBytes: output)
        }
        
        /// The size of the private key in bytes.
        private static let bytesCount = 64
    }
}

extension SLHDSA {
    /// A SLH-DSA-SHA2-128s public key.
    public struct PublicKey: Sendable {
        private let pointer: UnsafeMutablePointer<UInt8>
        
        fileprivate init(privateKey: PrivateKey) {
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SLHDSA.PublicKey.bytesCount)
            CCryptoBoringSSL_SLHDSA_SHA2_128S_public_from_private(self.pointer, privateKey.pointer)
        }
        
        public init(derRepresentation: some DataProtocol) throws {
            guard derRepresentation.count == SLHDSA.PublicKey.bytesCount else {
                throw CryptoKitError.incorrectKeySize
            }

            var keyDest: [UInt8] = Array(repeating: 0, count: SLHDSA.PublicKey.bytesCount)
            try keyDest.withUnsafeMutableBufferPointer { typedMemBuffer in
                guard derRepresentation.copyBytes(to: typedMemBuffer) == SLHDSA.PublicKey.bytesCount else {
                    throw CryptoKitError.incorrectKeySize
                }
            }

            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SLHDSA.PublicKey.bytesCount)
            self.pointer.initialize(from: keyDest, count: SLHDSA.PublicKey.bytesCount)
        }
        
        public init(pemRepresentation: String) throws {
            let document = try ASN1.PEMDocument(pemString: pemRepresentation)
            self = try .init(derRepresentation: document.derBytes)
        }

        public var bytes: [UInt8] {
            return Array(UnsafeBufferPointer(start: self.pointer, count: SLHDSA.PublicKey.bytesCount))
        }
        
        public var derRepresentation: Data {
            return Data(UnsafeBufferPointer(start: self.pointer, count: SLHDSA.PublicKey.bytesCount))
        }
        
        public var pemRepresentation: String {
            return ASN1.PEMDocument(type: SLHDSA.publicKeyType, derBytes: self.derRepresentation).pemString
        }
        
        public func isValidSignature(_ signature: Signature, for data: some DataProtocol, context: [UInt8]? = nil) -> Bool {
            signature.withUnsafeBytes { signaturePtr in
                let rc: CInt = data.regions.first!.withUnsafeBytes { dataPtr in
                    if let context {
                        context.withUnsafeBytes { contextPtr in
                            CCryptoBoringSSL_SLHDSA_SHA2_128S_verify(
                                signaturePtr.baseAddress,
                                signaturePtr.count,
                                self.pointer,
                                dataPtr.baseAddress,
                                dataPtr.count,
                                contextPtr.baseAddress,
                                contextPtr.count
                            )
                        }
                    } else {
                        CCryptoBoringSSL_SLHDSA_SHA2_128S_verify(
                            signaturePtr.baseAddress,
                            signaturePtr.count,
                            self.pointer,
                            dataPtr.baseAddress,
                            dataPtr.count,
                            nil,
                            0
                        )
                    }
                }
                return rc == 1
            }
        }
        
        /// The size of the public key in bytes.
        fileprivate static let bytesCount = 32
    }
}

extension SLHDSA {
    /// A SLH-DSA-SHA2-128s signature.
    public struct Signature: Sendable, ContiguousBytes {
        /// The raw binary representation of the signature.
        public var rawRepresentation: Data
        
        /// Initialize a SLH-DSA-SHA2-128s signature from a raw representation.
        /// 
        /// - Parameter rawRepresentation: The signature bytes.
        public init(rawRepresentation: some DataProtocol) {
            self.rawRepresentation = Data(rawRepresentation)
        }
        
        /// Initialize a SLH-DSA-SHA2-128s signature from a raw representation.
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
        fileprivate static let bytesCount = 7856
    }
}

extension SLHDSA {
    /// The ASN.1 object identifiers for a private SLH-DSA-SHA2-128s key.
    private static let keyType = "PRIVATE KEY"
    
    /// The ASN.1 object identifiers for a public SLH-DSA-SHA2-128s key.
    private static let publicKeyType = "PUBLIC KEY"
    
    /// The size of the seed in bytes.
    private static let seedSizeInBytes = 3 * 16
}
