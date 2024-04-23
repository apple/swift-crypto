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
            let seedPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 3 * 16)
            seedPointer.initialize(from: seed, count: 3 * 16)
            CCryptoBoringSSL_spx_generate_key_from_seed(UnsafeMutablePointer<UInt8>.allocate(capacity: 32), self.pointer, seedPointer)
        }
        
        public var bytes: [UInt8] {
            return Array(UnsafeBufferPointer(start: self.pointer, count: 64))
        }

        public var publicKey: PublicKey {
            return PublicKey(privateKey: self)
        }
        
        public func signature(for message: [UInt8], randomized: Bool = false) -> Signature {
            let messagePointer = UnsafeMutablePointer<UInt8>.allocate(capacity: message.count)
            messagePointer.initialize(from: message, count: message.count)
            let signaturePointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 7856)
            CCryptoBoringSSL_spx_sign(signaturePointer, self.pointer, messagePointer, message.count, randomized ? 1 : 0)
            let signatureBytes = Array(UnsafeBufferPointer(start: signaturePointer, count: 7856))
            return Signature(signatureBytes: signatureBytes)
        }
    }
}

extension SPX {
    public struct PublicKey: Sendable {
        private let pointer: UnsafeMutablePointer<UInt8>
        
        public init(privateKey: PrivateKey) {
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
            self.pointer.initialize(from: privateKey.bytes.suffix(32), count: 32)
        }
        
        public var bytes: [UInt8] {
            return Array(UnsafeBufferPointer(start: self.pointer, count: 32))
        }
        
        public func isValidSignature(_ signature: Signature, for message: [UInt8]) -> Bool {
            let messagePointer = UnsafeMutablePointer<UInt8>.allocate(capacity: message.count)
            messagePointer.initialize(from: message, count: message.count)
            var signatureBytes: [UInt8] = []
            signature.withUnsafeBytes {
                signatureBytes.append(contentsOf: $0)
            }
            let signaturePointer = UnsafeMutablePointer<UInt8>.allocate(capacity: signatureBytes.count)
            signaturePointer.initialize(from: signatureBytes, count: signatureBytes.count)
            return (CCryptoBoringSSL_spx_verify(signaturePointer, self.pointer, messagePointer, message.count) == 1)
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
