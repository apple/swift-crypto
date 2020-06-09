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
import Foundation

/// The size of a symmetric key
public struct SymmetricKeySize {
    public let bitCount: Int

    /// Symmetric key size of 128 bits
    public static var bits128: SymmetricKeySize {
        return self.init(bitCount: 128)
    }

    /// Symmetric key size of 128 bits
    public static var bits192: SymmetricKeySize {
        return self.init(bitCount: 192)
    }

    /// Symmetric key size of 256 bits
    public static var bits256: SymmetricKeySize {
        return self.init(bitCount: 256)
    }
    
    /// Symmetric key size with a custom number of bits.
    ///
    /// Params:
    ///     - bitsCount: Positive integer that is a multiple of 8.
    public init(bitCount: Int) {
        precondition(bitCount > 0 && bitCount % 8 == 0)
        self.bitCount = bitCount
    }
}

/// A symmetric key for use with software implementations of cryptographic algorithms.
public struct SymmetricKey: ContiguousBytes {
    let sb: SecureBytes

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try sb.withUnsafeBytes(body)
    }

    /// Initializes a key with data
    public init<D: ContiguousBytes>(data: D) {
        self.init(key: SecureBytes(bytes: data))
    }

    /// Generates a key of the provided key size
    ///
    /// - Parameter size: The key size
    public init(size: SymmetricKeySize) {
        self.init(key: SecureBytes(count: Int(size.bitCount / 8)))
    }

    /// The key size in bits
    public var bitCount: Int {
        return self.byteCount * 8
    }
    
    var byteCount: Int {
        return self.withUnsafeBytes({ (rbf) in
            return rbf.count
        })
    }

    private init(key: SecureBytes) {
        sb = key
    }
}

extension SymmetricKey: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        return safeCompare(lhs, rhs)
    }
}

#endif // Linux or !SwiftPM
