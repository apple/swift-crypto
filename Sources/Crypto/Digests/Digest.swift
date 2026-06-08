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
#if CRYPTOKIT_STATIC_LIBRARY
@_exported import CryptoKit_Static
#else
@_exported import CryptoKit
#endif
#else

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
public import SwiftSystem
#elseif CRYPTOKIT_NO_IMPORT_FOUNDATION
#else
#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif
#endif

#if hasFeature(Embedded)
/// A type that represents the output of a hash.
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
@preconcurrency
public protocol Digest: Hashable, Sendable, ContiguousBytes, Sequence where Element == UInt8 {
    /// The number of bytes in the digest.
    static var byteCount: Int { get }
}
#else // hasFeature(Embedded)
/// A type that represents the output of a hash.
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
@preconcurrency
public protocol Digest: Hashable, Sendable, ContiguousBytes, CustomStringConvertible, Sequence where Element == UInt8 {
    /// The number of bytes in the digest.
    static var byteCount: Int { get }
}
#endif // hasFeature(Embedded)

#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
protocol DigestPrivate: Digest {
    init?(initializingWith body: (inout OutputRawSpan) -> ())
}

#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
extension DigestPrivate {
    @inlinable
    init?(copying bytes: RawSpan) {
        self.init() {
            $0.append(contentsOf: bytes)
        }
    }
}

#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
extension Digest {
    public func makeIterator() -> Array<UInt8>.Iterator {
        self.withUnsafeBytes({ (buffPtr) in
            return Array(buffPtr).makeIterator()
        })
    }
}

// We want to implement constant-time comparison for digests.
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
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
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
extension Digest {
    public var description: String {
        return "\(Self.self): \(Array(self).hexString)"
    }
}
#endif

#endif // Linux or !SwiftPM
