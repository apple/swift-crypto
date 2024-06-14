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

@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
import Crypto
@_implementationOnly import CryptoBoringWrapper
import Foundation

#if swift(>=5.8)
@_documentation(visibility: public)
public enum SPX {}
#else
public enum SPX {}
#endif

extension SPX {
    public struct PrivateKey: Sendable {
        private let pointer: UnsafeMutablePointer<UInt8>
        
        public init() {
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.PrivateKey.bytesCount)
            CCryptoBoringSSL_spx_generate_key(UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.PublicKey.bytesCount), self.pointer)
        }
        
        public init(from seed: some DataProtocol) throws {
            guard seed.count >= SPX.seedSizeInBytes else {
                throw CryptoKitError.incorrectKeySize
            }
            let seedPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.seedSizeInBytes)
            seedPtr.initialize(from: seed.regions.flatMap { $0 }, count: SPX.seedSizeInBytes)
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.PrivateKey.bytesCount)
            CCryptoBoringSSL_spx_generate_key_from_seed(UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.PublicKey.bytesCount), self.pointer, seedPtr)
        }

        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            guard derRepresentation.count == SPX.PrivateKey.bytesCount else {
                throw CryptoKitError.incorrectKeySize
            }
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.PrivateKey.bytesCount)
            self.pointer.initialize(from: derRepresentation.regions.flatMap { $0 }, count: SPX.PrivateKey.bytesCount)
        }
        
        public init(pemRepresentation: String) throws {
            let document = try ASN1.PEMDocument(pemString: pemRepresentation)
            self = try .init(derRepresentation: document.derBytes)
        }

        public var bytes: [UInt8] {
            return Array(UnsafeBufferPointer(start: self.pointer, count: SPX.PrivateKey.bytesCount))
        }
        
        public var derRepresentation: Data {
            return Data(UnsafeBufferPointer(start: self.pointer, count: SPX.PrivateKey.bytesCount))
        }
        
        public var pemRepresentation: String {
            return ASN1.PEMDocument(type: SPX.KeyType, derBytes: self.derRepresentation).pemString
        }

        public var publicKey: PublicKey {
            return PublicKey(privateKey: self)
        }

        public func signature<D: DataProtocol>(for data: D, randomized: Bool = false) -> Signature {
            let output = Array<UInt8>(unsafeUninitializedCapacity: Signature.bytesCount) { bufferPtr, length in
                data.regions.first!.withUnsafeBytes { dataPtr in
                    CCryptoBoringSSL_spx_sign(
                        bufferPtr.baseAddress,
                        self.pointer,
                        dataPtr.baseAddress,
                        dataPtr.count,
                        randomized ? 1 : 0
                    )
                }
                length = Signature.bytesCount
            }
            return Signature(signatureBytes: output)
        }
        
        public static let bytesCount = 64
    }
}

extension SPX {
    public struct PublicKey: Sendable {
        private let pointer: UnsafeMutablePointer<UInt8>
        
        fileprivate init(privateKey: PrivateKey) {
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.PublicKey.bytesCount)
            self.pointer.initialize(from: privateKey.bytes.suffix(SPX.PublicKey.bytesCount), count: SPX.PublicKey.bytesCount)
        }
        
        public init(from seed: some DataProtocol) throws {
            guard seed.count >= SPX.seedSizeInBytes else {
                throw CryptoKitError.incorrectKeySize
            }
            let seedPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.seedSizeInBytes)
            seedPtr.initialize(from: seed.regions.flatMap { $0 }, count: SPX.seedSizeInBytes)
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.PublicKey.bytesCount)
            CCryptoBoringSSL_spx_generate_key_from_seed(self.pointer, UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.PrivateKey.bytesCount), seedPtr)
        }
        
        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            guard derRepresentation.count == SPX.PublicKey.bytesCount else {
                throw CryptoKitError.incorrectKeySize
            }
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.PublicKey.bytesCount)
            self.pointer.initialize(from: derRepresentation.regions.flatMap { $0 }, count: SPX.PublicKey.bytesCount)
        }
        
        public init(pemRepresentation: String) throws {
            let document = try ASN1.PEMDocument(pemString: pemRepresentation)
            self = try .init(derRepresentation: document.derBytes)
        }

        public var bytes: [UInt8] {
            return Array(UnsafeBufferPointer(start: self.pointer, count: SPX.PublicKey.bytesCount))
        }
        
        public var derRepresentation: Data {
            return Data(UnsafeBufferPointer(start: self.pointer, count: SPX.PublicKey.bytesCount))
        }
        
        public var pemRepresentation: String {
            return ASN1.PEMDocument(type: SPX.PublicKeyType, derBytes: self.derRepresentation).pemString
        }
        
        public func isValidSignature<D: DataProtocol>(_ signature: Signature, for data: D) -> Bool {
            return signature.withUnsafeBytes { signaturePtr in
                let rc: CInt = data.regions.first!.withUnsafeBytes { dataPtr in
                    return CCryptoBoringSSL_spx_verify(
                        signaturePtr.baseAddress,
                        self.pointer,
                        dataPtr.baseAddress,
                        dataPtr.count
                    )
                }
                return rc == 1
            }
        }
        
        public static let bytesCount = 32
    }
}

extension SPX {
    public struct Signature: Sendable, ContiguousBytes {
        public var rawRepresentation: Data
        
        public init<D: DataProtocol>(rawRepresentation: D) {
            self.rawRepresentation = Data(rawRepresentation)
        }
        
        internal init(signatureBytes: [UInt8]) {
            self.rawRepresentation = Data(signatureBytes)
        }
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }
        
        public static let bytesCount = 7856
    }
}

extension SPX {
    static let KeyType = "PRIVATE KEY"
    
    static let PublicKeyType = "PUBLIC KEY"
    
    public static let seedSizeInBytes = 3 * 16
}
