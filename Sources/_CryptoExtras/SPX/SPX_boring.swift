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
public enum _SPX { }
#else
public enum _SPX { }
#endif

extension _SPX {
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
        
        public func signature(for message: [UInt8], randomized: Bool = false) -> [UInt8] {
            let messagePointer = UnsafeMutablePointer<UInt8>.allocate(capacity: message.count)
            messagePointer.initialize(from: message, count: message.count)
            let signature = UnsafeMutablePointer<UInt8>.allocate(capacity: 7856)
            CCryptoBoringSSL_spx_sign(signature, self.pointer, messagePointer, message.count, randomized ? 1 : 0)
            return Array(UnsafeBufferPointer(start: signature, count: 7856))
        }
    }
}

extension _SPX {
    public struct PublicKey: Sendable {
        private let pointer: UnsafeMutablePointer<UInt8>
        
        public init(privateKey: PrivateKey) {
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
            self.pointer.initialize(from: privateKey.bytes.suffix(32), count: 32)
        }
        
        public var bytes: [UInt8] {
            return Array(UnsafeBufferPointer(start: self.pointer, count: 32))
        }
        
        public func isValidSignature(_ signature: [UInt8], for message: [UInt8]) -> Bool {
            let messagePointer = UnsafeMutablePointer<UInt8>.allocate(capacity: message.count)
            messagePointer.initialize(from: message, count: message.count)
            let signaturePointer = UnsafeMutablePointer<UInt8>.allocate(capacity: signature.count)
            signaturePointer.initialize(from: signature, count: signature.count)
            return (CCryptoBoringSSL_spx_verify(signaturePointer, self.pointer, messagePointer, message.count) == 1)
        }
    }
}
