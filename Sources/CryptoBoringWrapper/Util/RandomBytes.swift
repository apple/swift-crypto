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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension UnsafeMutableRawBufferPointer {
    @inlinable
    package func initializeWithRandomBytes(count: Int) {
        guard count > 0 else {
            return
        }

        #if canImport(Darwin) || os(Linux) || os(Android) || os(Windows) || os(FreeBSD) || os(OpenBSD)
        var rng = SystemRandomNumberGenerator()
        precondition(count <= self.count)

        // We store bytes 64-bits at a time until we can't anymore.
        var targetPtr = self
        while targetPtr.count > 8 {
            targetPtr.storeBytes(of: rng.next(), as: UInt64.self)
            targetPtr = UnsafeMutableRawBufferPointer(rebasing: targetPtr[8...])
        }

        // Now we're down to having to store things an integer at a time. We do this by shifting and
        // masking.
        var remainingWord: UInt64 = rng.next()
        while targetPtr.count > 0 {
            targetPtr.storeBytes(of: UInt8(remainingWord & 0xFF), as: UInt8.self)
            remainingWord >>= 8
            targetPtr = UnsafeMutableRawBufferPointer(rebasing: targetPtr[1...])
        }
        #else
        fatalError("No secure random number generator on this platform.")
        #endif
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SystemRandomNumberGenerator {
    @inlinable
    package static func randomBytes(count: Int) -> [UInt8] {
        Array(unsafeUninitializedCapacity: count) { buffer, initializedCount in
            UnsafeMutableRawBufferPointer(start: buffer.baseAddress, count: buffer.count)
                .initializeWithRandomBytes(count: count)
            initializedCount = count
        }
    }
}
