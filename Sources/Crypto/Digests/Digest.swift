//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(CryptoKit)
@_exported import CryptoKit
#else

#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif

#if hasFeature(Embedded)
/// A type that represents the output of a hash.
@preconcurrency
public protocol Digest: Hashable, Sendable, ContiguousBytes, Sequence where Element == UInt8 {
    /// The number of bytes in the digest.
    static var byteCount: Int { get }
}
#else
/// A type that represents the output of a hash.
@preconcurrency
public protocol Digest: Hashable, Sendable, ContiguousBytes, CustomStringConvertible, Sequence where Element == UInt8 {
    /// The number of bytes in the digest.
    static var byteCount: Int { get }
}
#endif // hasFeature(Embedded)

protocol DigestPrivate: Digest {
    init?(initializingWith body: (inout OutputRawSpan) -> ())
}

extension DigestPrivate {
    @inlinable
    init?(copying bytes: RawSpan) {
        self.init() {
            $0.append(contentsOf: bytes)
        }
    }
}

extension Digest {
    public func makeIterator() -> Array<UInt8>.Iterator {
        self.withUnsafeBytes({ (buffPtr) in
            return Array(buffPtr).makeIterator()
        })
    }
}

// We want to implement constant-time comparison for digests.
extension Digest {
    /// Determines whether two digests are equal.
    ///
    /// - Parameters:
    ///   - lhs: The first digest to compare.
    ///   - rhs: The second digest to compare.
    ///
    /// - Returns: A Boolean value set to `true` if the two digests are equal.
    public static func == (lhs: Self, rhs: Self) -> Bool {
        return safeCompare(lhs, rhs)
	}
    
    /// Determines whether a digest is equivalent to a collection of contiguous
    /// bytes.
    ///
    /// - Parameters:
    ///   - lhs: A digest to compare.
    ///   - rhs: A collection of contiguous bytes to compare.
    ///
    /// - Returns: A Boolean value that’s `true` if the digest is equivalent to
    /// the collection of binary data.
    public static func == <D: DataProtocol>(lhs: Self, rhs: D) -> Bool {
        if rhs.regions.count != 1 {
            let rhsContiguous = Data(rhs)
            return safeCompare(lhs, rhsContiguous)
        } else {
            return safeCompare(lhs, rhs.regions.first!)
        }
    }
}

#if !hasFeature(Embedded)
extension Digest {
    public var description: String {
        return "\(Self.self): \(Array(self).hexString)"
    }
}
#endif

#endif // canImport(CryptoKit)
