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
        private var backing: Backing

        public init() {
            self.backing = Backing()
        }

        public init(derRepresentation: some DataProtocol) throws {
            self.backing = try Backing(derRepresentation: derRepresentation)
        }

        public init(pemRepresentation: String) throws {
            self.backing = try Backing(pemRepresentation: pemRepresentation)
        }

        public var derRepresentation: Data {
            self.backing.derRepresentation
        }

        public var pemRepresentation: String {
            self.backing.pemRepresentation
        }

        public var publicKey: PublicKey {
            self.backing.publicKey
        }

        public func signature(for data: some DataProtocol, context: [UInt8]? = nil) throws -> Signature {
            try self.backing.signature(for: data, context: context)
        }

        /// The size of the private key in bytes.
        private static let bytesCount = Backing.bytesCount

        fileprivate final class Backing {
            fileprivate let pointer: UnsafeMutablePointer<UInt8>
            
            init() {
                self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SLHDSA.PrivateKey.bytesCount)

                let publicKeyPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: SLHDSA.PublicKey.bytesCount)
                defer { publicKeyPtr.deallocate() }

                CCryptoBoringSSL_SLHDSA_SHA2_128S_generate_key(publicKeyPtr, self.pointer)
            }

            init(derRepresentation: some DataProtocol) throws {
                guard derRepresentation.count == SLHDSA.PrivateKey.Backing.bytesCount else {
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
            
            convenience init(pemRepresentation: String) throws {
                let document = try ASN1.PEMDocument(pemString: pemRepresentation)
                try self.init(derRepresentation: document.derBytes)
            }
            
            var derRepresentation: Data {
                Data(UnsafeBufferPointer(start: self.pointer, count: SLHDSA.PrivateKey.bytesCount))
            }
            
            var pemRepresentation: String {
                ASN1.PEMDocument(type: SLHDSA.keyType, derBytes: self.derRepresentation).pemString
            }

            var publicKey: PublicKey {
                PublicKey(privateKeyBacking: self)
            }

            func signature(for data: some DataProtocol, context: [UInt8]? = nil) throws -> Signature {
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
            static let bytesCount = 64
        }
    }
}

extension SLHDSA {
    /// A SLH-DSA-SHA2-128s public key.
    public struct PublicKey: Sendable {
        private var backing: Backing

        fileprivate init(privateKeyBacking: PrivateKey.Backing) {
            self.backing = Backing(privateKeyBacking: privateKeyBacking)
        }

        public init(derRepresentation: some DataProtocol) throws {
            self.backing = try Backing(derRepresentation: derRepresentation)
        }

        public init(pemRepresentation: String) throws {
            self.backing = try Backing(pemRepresentation: pemRepresentation)
        }

        public var derRepresentation: Data {
            self.backing.derRepresentation
        }

        public var pemRepresentation: String {
            self.backing.pemRepresentation
        }

        public func isValidSignature(_ signature: Signature, for data: some DataProtocol, context: [UInt8]? = nil) -> Bool {
            self.backing.isValidSignature(signature, for: data, context: context)
        }

        /// The size of the public key in bytes.
        static let bytesCount = Backing.bytesCount

        fileprivate final class Backing {
            private let pointer: UnsafeMutablePointer<UInt8>
            
            init(privateKeyBacking: PrivateKey.Backing) {
                self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SLHDSA.PublicKey.bytesCount)
                CCryptoBoringSSL_SLHDSA_SHA2_128S_public_from_private(self.pointer, privateKeyBacking.pointer)
            }
            
            init(derRepresentation: some DataProtocol) throws {
                guard derRepresentation.count == Self.bytesCount else {
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
            
            convenience init(pemRepresentation: String) throws {
                let document = try ASN1.PEMDocument(pemString: pemRepresentation)
                try self.init(derRepresentation: document.derBytes)
            }
            
            var derRepresentation: Data {
                return Data(UnsafeBufferPointer(start: self.pointer, count: SLHDSA.PublicKey.bytesCount))
            }
            
            var pemRepresentation: String {
                return ASN1.PEMDocument(type: SLHDSA.publicKeyType, derBytes: self.derRepresentation).pemString
            }
            
            func isValidSignature(_ signature: Signature, for data: some DataProtocol, context: [UInt8]? = nil) -> Bool {
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
            static let bytesCount = 32
        }
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
        init(signatureBytes: [UInt8]) {
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
