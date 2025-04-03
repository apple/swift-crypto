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
import Foundation

/// A type that represents a message authentication code.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol MessageAuthenticationCode: Hashable, ContiguousBytes, CustomStringConvertible, Sequence where Element == UInt8 {
    /// The number of bytes in the message authentication code.
    var byteCount: Int { get }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MessageAuthenticationCode {
    /// Returns a Boolean value indicating whether two message authentication
    /// codes are equal.
    ///
    /// - Parameters:
    ///   - lhs: The first message authentication code to compare.
    ///   - rhs: The second message authentication code to compare.
    ///
    /// - Returns: A Boolean value that’s `true` if the message authentication
    /// codes are equivalent.
    public static func == (lhs: Self, rhs: Self) -> Bool {
        return safeCompare(lhs, rhs)
    }
    
    /// Returns a Boolean value indicating whether a message authentication code
    /// is equivalent to a collection of binary data.
    ///
    /// - Parameters:
    ///   - lhs: A message authentication code to compare.
    ///   - rhs: A collection of binary data to compare.
    ///
    /// - Returns: A Boolean value that’s `true` if the message authentication
    /// code and the collection of binary data are equivalent.
    public static func == <D: DataProtocol>(lhs: Self, rhs: D) -> Bool {
        if rhs.regions.count != 1 {
            let rhsContiguous = Data(rhs)
            return safeCompare(lhs, rhsContiguous)
        } else {
            return safeCompare(lhs, rhs.regions.first!)
        }
    }
    
    public func makeIterator() -> Array<UInt8>.Iterator {
        self.withUnsafeBytes({ (buffPtr) in
            return Array(buffPtr.bindMemory(to: UInt8.self)).makeIterator()
        })
    }

    public var description: String {
        return "\(Self.self): \(Array(self).hexString)"
    }
}
#endif // Linux or !SwiftPM
