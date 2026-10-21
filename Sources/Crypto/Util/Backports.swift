//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
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

#if swift(<6.4)

extension ContiguousBytes {
    func withBytes<R>(_ body: (RawSpan) throws -> R) rethrows -> R {
        try withUnsafeBytes { try body(RawSpan(_unsafeBytes: $0)) }
    }
}

extension MutableRawSpan {
    subscript(_ byteOffset: Int) -> UInt8 {
        get { unsafeLoad(fromByteOffset: byteOffset, as: UInt8.self) }
        #if swift(<6.3)
        @_lifetime(&self)
        set { storeBytes( of: newValue, toByteOffset: byteOffset, as: UInt8.self) }
        #else
        set { storeBytes( of: newValue, toByteOffset: byteOffset, as: UInt8.self) }
        #endif
  }
}

#endif // swift(6.4)
