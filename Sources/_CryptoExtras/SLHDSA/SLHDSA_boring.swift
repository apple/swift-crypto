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

import SwiftASN1
import Crypto
import Foundation

@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims

/// A stateless hash-based digital signature algorithm that provides security against quantum computing attacks.
public enum SLHDSA {}

extension SLHDSA {
    /// A SLH-DSA-SHA2-128s private key.
    public struct PrivateKey: Sendable {
        private var backing: Backing

        /// Initialize a SLH-DSA-SHA2-128s private key from a random seed.
        public init() {
            self.backing = Backing()
        }

        /// Initialize a SLH-DSA-SHA2-128s private key from a DER representation.
        /// 
        /// - Parameter derRepresentation: The DER representation of the private key.
        /// 
        /// - Throws: `CryptoKitError.wrapFailure` if the algorithm OID is not SLH-DSA-SHA2-128s.
        public init(derRepresentation: some DataProtocol) throws {
            self.backing = try Backing(derRepresentation: derRepresentation)
        }

        /// Initialize a SLH-DSA-SHA2-128s private key from a PEM representation.
        /// 
        /// - Parameter pemRepresentation: The PEM representation of the private key.
        public init(pemRepresentation: String) throws {
            self.backing = try Backing(pemRepresentation: pemRepresentation)
        }

        /// The DER representation of the private key.
        public var derRepresentation: Data {
            get throws {
                try self.backing.derRepresentation
            }
        }

        /// The PEM representation of the private key.
        public var pemRepresentation: String {
            get throws {
                try self.backing.pemRepresentation
            }
        }

        /// The public key associated with this private key.
        public var publicKey: PublicKey {
            self.backing.publicKey
        }

        /// Generate a signature for the given data.
        /// 
        /// - Parameters: 
        ///   - data: The message to sign.
        ///   - context: The context to use for the signature.
        /// 
        /// - Returns: The signature of the message.
        public func signature<D: DataProtocol>(for data: D, context: D? = nil) throws -> Signature {
            try self.backing.signature(for: data, context: context)
        }

        /// The size of the private key in bytes.
        private static let bytesCount = Backing.bytesCount

        fileprivate final class Backing {
            private let pointer: UnsafeMutablePointer<UInt8>

            func withUnsafePointer<T>(_ body: (UnsafePointer<UInt8>) throws -> T) rethrows -> T {
                try body(self.pointer)
            }
            
            /// Initialize a SLH-DSA-SHA2-128s private key from a random seed.
            init() {
                self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SLHDSA.PrivateKey.bytesCount)

                let publicKeyPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: SLHDSA.PublicKey.bytesCount)
                defer { publicKeyPtr.deallocate() }

                withUnsafeTemporaryAllocation(of: UInt8.self, capacity: SLHDSA.PublicKey.Backing.bytesCount) { publicKeyPtr in
                    CCryptoBoringSSL_SLHDSA_SHA2_128S_generate_key(publicKeyPtr.baseAddress, self.pointer)
                }
            }

            /// Initialize a SLH-DSA-SHA2-128s private key from a DER representation.
            /// 
            /// - Parameter derRepresentation: The DER representation of the private key.
            /// 
            /// - Throws: `CryptoKitError.wrapFailure` if the algorithm OID is not SLH-DSA-SHA2-128s.
            init(derRepresentation: some DataProtocol) throws {
                let result = try DER.parse(Array(derRepresentation))
                let pkey = try OneAsymmetricKey(derEncoded: result)

                guard pkey.algorithm == .slhDsaSHA2128s else {
                    throw CryptoKitError.wrapFailure
                }

                self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SLHDSA.PrivateKey.bytesCount)
                pkey.privateKey.withUnsafeBytes { keyPtr in
                    self.pointer.initialize(from: Array(keyPtr), count: SLHDSA.PrivateKey.bytesCount)
                }
            }
            
            /// Initialize a SLH-DSA-SHA2-128s private key from a PEM representation.
            /// 
            /// - Parameter pemRepresentation: The PEM representation of the private key.
            convenience init(pemRepresentation: String) throws {
                let document = try ASN1.PEMDocument(pemString: pemRepresentation)
                try self.init(derRepresentation: document.derBytes)
            }
            
            /// The DER representation of the private key.
            var derRepresentation: Data {
                get throws {
                    let keyBytes = Array(Data(UnsafeBufferPointer(start: self.pointer, count: SLHDSA.PrivateKey.bytesCount)))
                    let pkey = OneAsymmetricKey(algorithm: .slhDsaSHA2128s, privateKey: keyBytes)
                    var serializer = DER.Serializer()
                    try serializer.serialize(pkey)
                    return Data(serializer.serializedBytes)
                }
            }
            
            /// The PEM representation of the private key.
            var pemRepresentation: String {
                get throws {
                    try ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation).pemString
                }
            }
            
            /// The public key associated with this private key.
            var publicKey: PublicKey {
                PublicKey(privateKeyBacking: self)
            }

            /// Generate a signature for the given data.
            /// 
            /// - Parameters: 
            ///   - data: The message to sign.
            ///   - context: The context to use for the signature.
            /// 
            /// - Returns: The signature of the message.
            func signature<D: DataProtocol>(for data: D, context: D? = nil) throws -> Signature {
                let output = try Array<UInt8>(unsafeUninitializedCapacity: Signature.bytesCount) { bufferPtr, length in
                    let bytes: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                    let result = bytes.withUnsafeBytes { dataPtr in
                        if let context {
                            CCryptoBoringSSL_SLHDSA_SHA2_128S_sign(
                                bufferPtr.baseAddress,
                                self.pointer,
                                dataPtr.baseAddress,
                                dataPtr.count,
                                Array(context),
                                context.count
                            )
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

        /// Initialize a SLH-DSA-SHA2-128s public key from a DER representation.
        /// 
        /// - Parameter derRepresentation: The DER representation of the public key.
        /// 
        /// - Throws: `CryptoKitError.wrapFailure` if the algorithm OID is not SLH-DSA-SHA2-128s.
        public init(derRepresentation: some DataProtocol) throws {
            self.backing = try Backing(derRepresentation: derRepresentation)
        }

        /// Initialize a SLH-DSA-SHA2-128s public key from a PEM representation.
        /// 
        /// - Parameter pemRepresentation: The PEM representation of the public key.
        public init(pemRepresentation: String) throws {
            self.backing = try Backing(pemRepresentation: pemRepresentation)
        }

        /// The DER representation of the public key.
        public var derRepresentation: Data {
            get throws {
                try self.backing.derRepresentation
            }
        }

        /// The PEM representation of the public key.
        public var pemRepresentation: String {
            get throws {
                try self.backing.pemRepresentation
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
        public func isValidSignature<D: DataProtocol>(_ signature: Signature, for data: D, context: D? = nil) -> Bool {
            self.backing.isValidSignature(signature, for: data, context: context)
        }

        /// The size of the public key in bytes.
        fileprivate static let bytesCount = Backing.bytesCount

        fileprivate final class Backing {
            private let pointer: UnsafeMutablePointer<UInt8>
            
            init(privateKeyBacking: PrivateKey.Backing) {
                self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SLHDSA.PublicKey.bytesCount)
                privateKeyBacking.withUnsafePointer { privateKeyPtr in
                    CCryptoBoringSSL_SLHDSA_SHA2_128S_public_from_private(self.pointer, privateKeyPtr)
                }
            }
            
            /// Initialize a SLH-DSA-SHA2-128s public key from a DER representation.
            /// 
            /// - Parameter derRepresentation: The DER representation of the public key.
            /// 
            /// - Throws: `CryptoKitError.wrapFailure` if the algorithm OID is not SLH-DSA-SHA2-128s.
            init(derRepresentation: some DataProtocol) throws {
                let result = try DER.parse(Array(derRepresentation))
                let spki = try SubjectPublicKeyInfo(derEncoded: result)

                guard spki.algorithmIdentifier == .slhDsaSHA2128s else {
                    throw CryptoKitError.wrapFailure
                }

                self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SLHDSA.PublicKey.bytesCount)
                spki.key.withUnsafeBytes { keyPtr in
                    self.pointer.initialize(from: Array(keyPtr), count: SLHDSA.PublicKey.bytesCount)
                }
            }
            
            /// Initialize a SLH-DSA-SHA2-128s public key from a PEM representation.
            /// 
            /// - Parameter pemRepresentation: The PEM representation of the public key.
            convenience init(pemRepresentation: String) throws {
                let document = try ASN1.PEMDocument(pemString: pemRepresentation)
                try self.init(derRepresentation: document.derBytes)
            }
            
            /// The DER representation of the public key.
            var derRepresentation: Data {
                get throws {
                    let keyBytes = Array(Data(UnsafeBufferPointer(start: self.pointer, count: SLHDSA.PublicKey.bytesCount)))
                    let spki = SubjectPublicKeyInfo(algorithmIdentifier: .slhDsaSHA2128s, key: keyBytes)
                    var serializer = DER.Serializer()
                    try serializer.serialize(spki)
                    return Data(serializer.serializedBytes)
                }
            }
            
            /// The PEM representation of the public key.
            var pemRepresentation: String {
                get throws {
                    try ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation).pemString
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
            func isValidSignature<D: DataProtocol>(_ signature: Signature, for data: D, context: D? = nil) -> Bool {
                signature.withUnsafeBytes { signaturePtr in
                    let bytes: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                    let rc: CInt = bytes.withUnsafeBytes { dataPtr in
                        if let context {
                            CCryptoBoringSSL_SLHDSA_SHA2_128S_verify(
                                signaturePtr.baseAddress,
                                signaturePtr.count,
                                self.pointer,
                                dataPtr.baseAddress,
                                dataPtr.count,
                                Array(context),
                                context.count
                            )
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
