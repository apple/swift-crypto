//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
import SwiftSystem
#else
import Foundation
#endif
// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.




// MARK: - AES.GCM + Nonce
extension AES.GCM {
    /// A value used once during a cryptographic operation and then discarded.
    ///
    /// Don’t reuse the same nonce for multiple calls to encryption APIs. It’s critical
    /// that nonces are unique per call to encryption APIs in order to protect the
    /// integrity of the encryption.
    public struct Nonce: ContiguousBytes, Sequence {
        let bytes: Data

        /// Creates a new random nonce.
        ///
        /// The default nonce is a 12-byte random nonce.
        public init() {
            var data = Data(repeating: 0, count: AES.GCM.defaultNonceByteCount)
            data.withUnsafeMutableBytes {
                assert($0.count == AES.GCM.defaultNonceByteCount)
                $0.initializeWithRandomBytes(count: AES.GCM.defaultNonceByteCount)
            }
            self.bytes = data
        }
        
        /// Creates a nonce from the given data.
        ///
        /// Unless your use case calls for a nonce with a specific value, use the
        /// ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
///   - data: A data representation of the nonce.
///     The initializer throws an error if the data has a length smaller than 12 bytes.
        public init<D: DataProtocol>(data: D) throws {
            if data.count < AES.GCM.defaultNonceByteCount {
                throw CryptoKitError.incorrectParameterSize
            }

            self.bytes = Data(data)
        }
        
        /// Calls the given closure with a pointer to the underlying bytes of the array’s
        /// contiguous storage.
        ///
        /// - Parameters:
        ///   - body: A closure with an `UnsafeRawBufferPointer` parameter that points to the
        /// contiguous storage for the array. The system creates the storage if it doesn’t
        /// exist. If body has a return value, that value is also used as the return value
        /// for the ``withUnsafeBytes(_:)`` method. The argument is valid only for
        /// the duration of the closure’s execution.
        ///
        /// - Returns: The return value, if any, of the body closure parameter.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        
        /// Returns an iterator over the elements of the nonce.
        public func makeIterator() -> Array<UInt8>.Iterator {
            self.withUnsafeBytes({ (buffPtr) in
                return Array(buffPtr).makeIterator()
            })
        }
    }
}

// MARK: - ChaChaPoly + Nonce
extension ChaChaPoly {
    /// A value used once during a cryptographic operation and then discarded.
    ///
    /// Don’t reuse the same nonce for multiple calls to encryption APIs. It’s critical
    /// that nonces are unique per call to encryption APIs in order to protect the
    /// integrity of the encryption.
    public struct Nonce: ContiguousBytes, Sequence {
        let bytes: Data

        /// Creates a new random nonce.
        ///
        /// The default nonce is a 12-byte random nonce.
        public init() {
            var data = Data(repeating: 0, count: ChaChaPoly.nonceByteCount)
            data.withUnsafeMutableBytes {
                assert($0.count == ChaChaPoly.nonceByteCount)
                $0.initializeWithRandomBytes(count: ChaChaPoly.nonceByteCount)
            }
            self.bytes = data
        }
        
        /// Creates a nonce from the given data.
        ///
        /// Unless your use case calls for a nonce with a specific value, use the
        /// ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
///   - data: A 12-byte data representation of the nonce.
///     The initializer throws an error if the data isn't 12 bytes long.
        public init<D: DataProtocol>(data: D) throws {
            if data.count != ChaChaPoly.nonceByteCount {
                throw CryptoKitError.incorrectParameterSize
            }

            self.bytes = Data(data)
        }
        
        /// Calls the given closure with a pointer to the underlying bytes of the array’s
        /// contiguous storage.
        ///
        /// - Parameters:
        ///   - body: A closure with an `UnsafeRawBufferPointer` parameter that points to the
        /// contiguous storage for the array. The system creates the storage if it doesn’t
        /// exist. If body has a return value, that value is also used as the return value
        /// for the ``withUnsafeBytes(_:)`` method. The argument is valid only for
        /// the duration of the closure’s execution.
        ///
        /// - Returns: The return value, if any, of the body closure parameter.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        
        /// Returns an iterator over the elements of the nonce.
        public func makeIterator() -> Array<UInt8>.Iterator {
            self.withUnsafeBytes({ (buffPtr) in
                return Array(buffPtr).makeIterator()
            })
        }
    }
}
#endif // Linux or !SwiftPM
