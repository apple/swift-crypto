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
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
extension Insecure {
    /// The SHA-1 Hash Function.
    /// ⚠️ Security Recommendation: The SHA-1 hash function is no longer considered secure. We strongly recommend using the SHA-256 hash function instead.
    public struct SHA1: HashFunctionImplementationDetails {
        public static var blockByteCount: Int {
            get { return 64 }
            
            set { fatalError("Cannot set SHA1.blockByteCount") }
        }
        
        public static var byteCount: Int {
            get { return 20 }
            
            set { fatalError("Cannot set SHA1.byteCount") }
        }
        
        public typealias Digest = Insecure.SHA1Digest
        var impl: DigestImpl<SHA1>

        /// Initializes the hash function instance.
        public init() {
            impl = DigestImpl()
        }

        public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
            impl.update(data: bufferPointer)
        }

        /// Returns the digest from the data input in the hash function instance.
        ///
        /// - Returns: The digest of the inputted data
        public func finalize() -> Self.Digest {
            return impl.finalize()
        }
    }

    /// The MD5 Hash Function.
    /// ⚠️ Security Recommendation: The MD5 hash function is no longer considered secure. We strongly recommend using the SHA-256 hash function instead.
    public struct MD5: HashFunctionImplementationDetails {
        public static var blockByteCount: Int {
            get { return 64 }
            
            set { fatalError("Cannot set MD5.blockByteCount") }
        }
        public static var byteCount: Int {
            get { return 16 }
            
            set { fatalError("Cannot set MD5.byteCount") }
        }
        
        public typealias Digest = Insecure.MD5Digest
        var impl: DigestImpl<MD5>

        /// Initializes the hash function instance.
        public init() {
            impl = DigestImpl()
        }

        public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
            impl.update(data: bufferPointer)
        }

        /// Returns the digest from the data input in the hash function instance.
        ///
        /// - Returns: The digest of the inputted data
        public func finalize() -> Self.Digest {
            return impl.finalize()
        }
    }
}
#endif  // Linux or !SwiftPM
