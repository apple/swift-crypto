//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
import Foundation

extension AES.GCM {
    public struct Nonce: ContiguousBytes, Sequence {
        let bytes: Data

        /// Generates a fresh random Nonce. Unless required by a specification to provide a specific Nonce, this is the recommended initializer.
        public init() {
            try! self.init(data: SecureBytes(count: AES.GCM.defaultNonceByteCount))
        }

        public init<D: DataProtocol>(data: D) throws {
            if data.count < AES.GCM.defaultNonceByteCount {
                throw CryptoKitError.incorrectParameterSize
            }

            self.bytes = Data(data)
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }

        public func makeIterator() -> Array<UInt8>.Iterator {
            self.withUnsafeBytes { buffPtr in
                Array(buffPtr).makeIterator()
            }
        }
    }
}

extension ChaChaPoly {
    public struct Nonce: ContiguousBytes, Sequence {
        let bytes: Data

        /// Generates a fresh random Nonce. Unless required by a specification to provide a specific Nonce, this is the recommended initializer.
        public init() {
            try! self.init(data: SecureBytes(count: ChaChaPoly.nonceByteCount))
        }

        public init<D: DataProtocol>(data: D) throws {
            if data.count != ChaChaPoly.nonceByteCount {
                throw CryptoKitError.incorrectParameterSize
            }

            self.bytes = Data(data)
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }

        public func makeIterator() -> Array<UInt8>.Iterator {
            self.withUnsafeBytes { buffPtr in
                Array(buffPtr).makeIterator()
            }
        }
    }
}
#endif // Linux or !SwiftPM
