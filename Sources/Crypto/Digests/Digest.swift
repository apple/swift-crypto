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

/// A protocol defining requirements for digests
public protocol Digest: Hashable, ContiguousBytes, CustomStringConvertible, Sequence where Element == UInt8 {
    static var byteCount: Int { get }
}

protocol DigestPrivate: Digest {
    init?(bufferPointer: UnsafeRawBufferPointer)
}

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

extension Digest {
    public func makeIterator() -> Array<UInt8>.Iterator {
        self.withUnsafeBytes({ (buffPtr) in
            return Array(buffPtr).makeIterator()
        })
    }
}

// We want to implement constant-time comparison for digests.
extension Digest {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        return safeCompare(lhs, rhs)
	}
    
    public static func == <D: DataProtocol>(lhs: Self, rhs: D) -> Bool {
        if rhs.regions.count != 1 {
            let rhsContiguous = Data(rhs)
            return safeCompare(lhs, rhsContiguous)
        } else {
            return safeCompare(lhs, rhs.regions.first!)
        }
    }

    public var description: String {
        return "\(Self.self): \(Array(self).hexString)"
    }
}
#endif // Linux or !SwiftPM
