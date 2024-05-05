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
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 64)
            CCryptoBoringSSL_spx_generate_key(UnsafeMutablePointer<UInt8>.allocate(capacity: 32), self.pointer)
        }
        
        public init(from seed: [UInt8]) {
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 64)
            let seedPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: 3 * 16)
            seedPtr.initialize(from: seed, count: 3 * 16)
            CCryptoBoringSSL_spx_generate_key_from_seed(UnsafeMutablePointer<UInt8>.allocate(capacity: 32), self.pointer, seedPtr)
        }
        
        public var bytes: [UInt8] {
            return Array(UnsafeBufferPointer(start: self.pointer, count: 64))
        }

        public var publicKey: PublicKey {
            return PublicKey(privateKey: self)
        }
        
        public func signature<D: Digest>(for digest: D, randomized: Bool = false) -> Signature {
            let output = Array<UInt8>(unsafeUninitializedCapacity: 7856) { bufferPtr, length in
                digest.withUnsafeBytes { digestPtr in
                    CCryptoBoringSSL_spx_sign(
                        bufferPtr.baseAddress,
                        self.pointer,
                        digestPtr.baseAddress,
                        digestPtr.count,
                        randomized ? 1 : 0
                    )
                }
                length = 7856
            }
            return Signature(signatureBytes: output)
        }

        public func signature<D: DataProtocol>(for data: D, randomized: Bool = false) -> Signature {
            self.signature(for: SHA256.hash(data: data), randomized: randomized)
        }
    }
}

extension SPX {
    public struct PublicKey: Sendable {
        private let pointer: UnsafeMutablePointer<UInt8>
        
        fileprivate init(privateKey: PrivateKey) {
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
            self.pointer.initialize(from: privateKey.bytes.suffix(32), count: 32)
        }
        
        public init(from seed: [UInt8]) {
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
            let seedPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: 3 * 16)
            seedPtr.initialize(from: seed, count: 3 * 16)
            CCryptoBoringSSL_spx_generate_key_from_seed(self.pointer, UnsafeMutablePointer<UInt8>.allocate(capacity: 64), seedPtr)
        }
        
        public var bytes: [UInt8] {
            return Array(UnsafeBufferPointer(start: self.pointer, count: 32))
        }
        
        public func isValidSignature<D: Digest>(_ signature: Signature, for digest: D) -> Bool {
            return signature.withUnsafeBytes { signaturePtr in
                let rc: CInt = digest.withUnsafeBytes { digestPtr in
                    return CCryptoBoringSSL_spx_verify(
                        signaturePtr.baseAddress,
                        self.pointer,
                        digestPtr.baseAddress,
                        digestPtr.count
                    )
                }
                return rc == 1
            }
        }
        
        public func isValidSignature<D: DataProtocol>(_ signature: Signature, for data: D) -> Bool {
            self.isValidSignature(signature, for: SHA256.hash(data: data))
        }
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
    }
}
