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

protocol Zeroization {
    mutating func zeroize()
}

extension UnsafeMutablePointer: Zeroization {
    /// Zeroizes the pointee
    func zeroize() {
        let size = MemoryLayout.size(ofValue: Pointee.self)
        memset_s(self, size, 0, size)
    }
}

extension UnsafeMutableRawBufferPointer: Zeroization {
    func zeroize() {
        memset_s(self.baseAddress, self.count, 0, self.count)
    }
}

extension Array: Zeroization where Element == UInt8 {
    /// Zeroizes the array
    mutating func zeroize() {
        memset_s(&self, self.count, 0, self.count)
    }
}

extension Data: Zeroization {
    internal mutating func zeroize() {
        _ = self.withUnsafeMutableBytes {
            memset_s($0.baseAddress!, $0.count, 0, $0.count)
        }
    }
}

#endif // Linux or !SwiftPM
