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
import XCTest

#if canImport(CryptoKit)
// Skip tests that require @testable imports of CryptoKit.
#else
@testable import Crypto

extension ECKeyEncodingsTests {
    func testCompactRepresentabilityIsDecidedByTheFieldPrime() throws {
        // y = n + 1, the larger of the two square roots, so not compact representable.
        let aboveMidpointX = try Data(hexString: "d1db3668128866847e66864aa97c37a04f65f6ff201a7d02345dffd738908975")
        let aboveMidpointY = try Data(hexString: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552")
        let aboveMidpoint = try P256.Signing.PublicKey(rawRepresentation: aboveMidpointX + aboveMidpointY)
        XCTAssertNil(aboveMidpoint.compactRepresentation)

        // n/2 < y <= (p-1)/2, the smaller of the two square roots, so compact representable.
        let belowMidpointX = try Data(hexString: "ce2afeafa686293c6c93f644b3f6d796c659a9277ca4af6c15ef3bfdc6e00f89")
        let belowMidpointY = try Data(hexString: "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192aa")
        let belowMidpoint = try P256.Signing.PublicKey(rawRepresentation: belowMidpointX + belowMidpointY)
        XCTAssertEqual(belowMidpoint.compactRepresentation, belowMidpointX)
    }
}

#endif  // canImport(CryptoKit)
