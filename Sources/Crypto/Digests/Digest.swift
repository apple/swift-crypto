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
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
public import SwiftSystem
#else
#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif
#endif

#if hasFeature(Embedded)
/// A type that represents the output of a hash.
@preconcurrency
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol Digest: Hashable, Sendable, ContiguousBytes, Sequence where Element == UInt8 {
    /// The number of bytes in the digest.
    static var byteCount: Int { get }
}
#else // hasFeature(Embedded)
/// A type that represents the output of a hash.
@preconcurrency
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol Digest: Hashable, Sendable, ContiguousBytes, CustomStringConvertible, Sequence where Element == UInt8 {
    /// The number of bytes in the digest.
    static var byteCount: Int { get }
}
#endif // hasFeature(Embedded)

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol DigestPrivate: Digest {
    init?(bufferPointer: UnsafeRawBufferPointer)
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension DigestPrivate {
    @inlinable
    init?(bytes: [UInt8]) {
        let some = bytes.withUnsafeBytes { bufferPointer in
            return Self(bufferPointer: bufferPointer)
        }
        
        if some != nil {
            self = some!
        } else {
            return nil
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Digest {
    public func makeIterator() -> Array<UInt8>.Iterator {
        self.withUnsafeBytes({ (buffPtr) in
            return Array(buffPtr).makeIterator()
        })
    }
}

// We want to implement constant-time comparison for digests.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Digest {
    public var description: String {
        return "\(Self.self): \(Array(self).hexString)"
    }
}
#endif

#endif // Linux or !SwiftPM
