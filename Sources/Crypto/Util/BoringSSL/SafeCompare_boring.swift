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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// This function performs a safe comparison between two buffers of bytes. It exists as a temporary shim until we refactor
/// some of the usage sites to pass better data structures to us.
@inlinable
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
internal func openSSLSafeCompare<LHS: ContiguousBytes, RHS: ContiguousBytes>(
    _ lhs: LHS,
    _ rhs: RHS
)
    -> Bool
{
    lhs.withUnsafeBytes { lhsPtr in
        rhs.withUnsafeBytes { rhsPtr in
            constantTimeCompare(lhsPtr, rhsPtr)
        }
    }
}

/// A straightforward constant-time comparison function for any two collections of bytes.
@inlinable
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
internal func constantTimeCompare<LHS: Collection, RHS: Collection>(_ lhs: LHS, _ rhs: RHS) -> Bool
where LHS.Element == UInt8, RHS.Element == UInt8 {
    guard lhs.count == rhs.count else {
        return false
    }

    return zip(lhs, rhs).reduce(into: 0) { $0 |= $1.0 ^ $1.1 } == 0
}
