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

import XCTest

#if canImport(CryptoKit)
// Skip tests that require @testable imports of CryptoKit.
#else
@testable import Crypto

class SymmetricKeyTests: XCTestCase {
    func testBytesZeroing() throws {
        var myData: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]

        let simpleKey = myData.withUnsafeBytes { buffer in
            SymmetricKey(data: buffer)
        }

        do {
            var span = myData.mutableSpan
            var rawSpan = span.mutableBytes
            let key = SymmetricKey(copyingWithZeroing: &rawSpan)
            assert(key.bytes == simpleKey.bytes)
        }

        assert(myData == [0, 0, 0, 0, 0, 0, 0, 0])
    }
}

extension RawSpan {
    static func ==(lhs: RawSpan, rhs: RawSpan) -> Bool {
        lhs.withUnsafeBytes { lhsBuffer in
            rhs.withUnsafeBytes { rhsBuffer in
                lhsBuffer.elementsEqual(rhsBuffer)
            }
        }
    }
}
#endif
