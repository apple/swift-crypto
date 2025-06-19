//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import CryptoBoringWrapper
import XCTest

final class EllipticCurvePointTests: XCTestCase {
    static let p256 = try! BoringSSLEllipticCurveGroup(.p256)

    func testRepeatedMultiplyHasValueSemantics() throws {
        let point = Self.p256.generator
        var copy = point
        try copy.multiply(by: 2, on: Self.p256)
        try copy.multiply(by: 2, on: Self.p256)

        XCTAssertTrue(!copy.isEqual(to: point, on: Self.p256))
        XCTAssertTrue(try copy.isEqual(to: point.multiplying(by: 4, on: Self.p256), on: Self.p256))
    }

    func testAddHasValueSemantics() throws {
        let point = Self.p256.generator
        var other = point
        try other.add(point, on: Self.p256)

        XCTAssertTrue(!other.isEqual(to: point, on: Self.p256))
        XCTAssertTrue(try other.isEqual(to: point.adding(point, on: Self.p256), on: Self.p256))
    }

    func testInvertingHasValueSemantics() throws {
        let point = try Self.p256.generator.multiplying(
            by: 2,
            on: Self.p256
        )
        var other = point
        try other.invert(on: Self.p256)

        XCTAssertTrue(!other.isEqual(to: point, on: Self.p256))
        XCTAssertTrue(try other.isEqual(to: point.inverting(on: Self.p256), on: Self.p256))
    }

    func testSubtractHasValueSemantics() throws {
        let point = Self.p256.generator
        var other = point
        try other.subtract(point, on: Self.p256)

        XCTAssertTrue(!other.isEqual(to: point, on: Self.p256))
        XCTAssertTrue(try other.isEqual(to: point.subtracting(point, on: Self.p256), on: Self.p256))
    }
}
