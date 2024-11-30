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

import XCTest

@testable import CryptoBoringWrapper

final class ArbitraryPrecisionIntegerTests: XCTestCase {
    func testSimpleArithmetic() {
        let six = ArbitraryPrecisionInteger(6)
        let twelve = ArbitraryPrecisionInteger(12)
        let result = six * twelve

        XCTAssertEqual(result, 72)
    }

    func testPositivity() {
        let six = ArbitraryPrecisionInteger(6)
        let negativeOne = ArbitraryPrecisionInteger(-1)
        XCTAssertFalse(negativeOne._positive)

        XCTAssertFalse((six * negativeOne)._positive)
        XCTAssertTrue((six * negativeOne * negativeOne)._positive)
    }

    func testSquaring() {
        let six = ArbitraryPrecisionInteger(6)
        XCTAssertEqual(six.squared(), 36)
        XCTAssertEqual(six, 6)
    }

    func testPositiveSquareRoot() {
        XCTAssertNoThrow(XCTAssertEqual(try ArbitraryPrecisionInteger(144).positiveSquareRoot(), 12))
        XCTAssertThrowsError(try ArbitraryPrecisionInteger(101).positiveSquareRoot()) { error in
            guard case .some(.underlyingCoreCryptoError) = error as? CryptoBoringWrapperError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
    }

    func testSimpleRepresentation() {
        let six = ArbitraryPrecisionInteger(60)
        XCTAssertEqual(six.debugDescription, "3c")
    }

    func testMoreArithmetic() {
        let fifteen = ArbitraryPrecisionInteger(15) + .zero
        let sixteen = fifteen + 1

        var sixteenTwo = sixteen
        sixteenTwo += 4
        let ten = sixteenTwo - 10
        sixteenTwo -= 4

        XCTAssertEqual(fifteen, 15)
        XCTAssertEqual(sixteen, 16)
        XCTAssertEqual(sixteenTwo, 16)
        XCTAssertEqual(ten, 10)
    }

    func testNegationAndAbsoluteValues() {
        let oneOhFour = ArbitraryPrecisionInteger(104)
        var copy = oneOhFour
        copy.negate()

        XCTAssertEqual(copy, ArbitraryPrecisionInteger(-104))
        XCTAssertEqual(copy.magnitude, oneOhFour.magnitude)
        XCTAssertEqual(copy.magnitude, oneOhFour)
    }

    func testAllInPlaceArithmeticCoWs() {
        let base = ArbitraryPrecisionInteger(5)
        var adder = base
        var subber = base
        var timeser = base

        adder += base
        subber -= base
        timeser *= base

        XCTAssertEqual(base, 5)
        XCTAssertEqual(adder, 10)
        XCTAssertEqual(subber, 0)
        XCTAssertEqual(timeser, 25)
    }

    func testComparable() {
        let one = ArbitraryPrecisionInteger(1)
        let two = ArbitraryPrecisionInteger(2)

        // Not using XCTAssertLessThan and friends
        // because we want to test these operators specifically.
        XCTAssertTrue(one < two)
        XCTAssertTrue(one <= two)
        XCTAssertFalse(one < one)
        XCTAssertTrue(one <= one)
        XCTAssertTrue(two > one)
        XCTAssertTrue(two >= one)
        XCTAssertFalse(two > two)
        XCTAssertTrue(two >= two)
    }

    func testGCD() {
        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(+9, +13), 1)
        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(+9, -13), 1)
        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(-9, +13), 1)
        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(-9, -13), 1)

        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(+13, +9), 1)
        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(+13, -9), 1)
        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(-13, +9), 1)
        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(-13, -9), 1)

        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(+9, +12), 3)
        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(+9, -12), 3)
        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(-9, +12), 3)
        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(-9, -12), 3)

        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(+12, +9), 3)
        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(+12, -9), 3)
        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(-12, +9), 3)
        XCTAssertEqual(try ArbitraryPrecisionInteger.gcd(-12, -9), 3)
    }

    func testIsCoprime() {
        XCTAssert(try ArbitraryPrecisionInteger(+9).isCoprime(with: +13))
        XCTAssert(try ArbitraryPrecisionInteger(+9).isCoprime(with: -13))
        XCTAssert(try ArbitraryPrecisionInteger(-9).isCoprime(with: +13))
        XCTAssert(try ArbitraryPrecisionInteger(-9).isCoprime(with: -13))

        XCTAssertFalse(try ArbitraryPrecisionInteger(+9).isCoprime(with: +27))
        XCTAssertFalse(try ArbitraryPrecisionInteger(+9).isCoprime(with: -27))
        XCTAssertFalse(try ArbitraryPrecisionInteger(-9).isCoprime(with: +27))
        XCTAssertFalse(try ArbitraryPrecisionInteger(-9).isCoprime(with: -27))
    }

    func testRandom() throws {
        XCTAssertEqual(try ArbitraryPrecisionInteger.random(inclusiveMin: 4, exclusiveMax: 5), 4)

        var previousRandom = ArbitraryPrecisionInteger()
        for _ in 1...1000 {
            let exclusiveMax = try ArbitraryPrecisionInteger(
                bytes: Data(repeating: UInt8.max, count: 2048 / 8)
            )
            let random = try ArbitraryPrecisionInteger.random(
                inclusiveMin: 42,
                exclusiveMax: exclusiveMax
            )
            XCTAssert(random >= ArbitraryPrecisionInteger(42))
            XCTAssert(random < exclusiveMax)
            XCTAssert(random != previousRandom)
            previousRandom = random
        }
    }

    func testDataRoundtrip() throws {
        for value: Int64 in [0, 1, 42, 256, 1024, .max] {
            let integer = ArbitraryPrecisionInteger(integerLiteral: value)
            let bytes = try Data(bytesOf: integer, paddedToSize: (value.bitWidth + 7) / 8)
            XCTAssertEqual(try ArbitraryPrecisionInteger(bytes: bytes), integer)
        }
    }

    func testMoudlo() throws {
        typealias I = ArbitraryPrecisionInteger
        typealias Vector = (input: I, mod: I, expectedResult: (standard: I, nonNegative: I))
        for vector: Vector in [
            (input: 0, mod: 2, expectedResult: (standard: 0, nonNegative: 0)),
            (input: 1, mod: 2, expectedResult: (standard: 1, nonNegative: 1)),
            (input: 2, mod: 2, expectedResult: (standard: 0, nonNegative: 0)),
            (input: 3, mod: 2, expectedResult: (standard: 1, nonNegative: 1)),
            (input: 4, mod: 2, expectedResult: (standard: 0, nonNegative: 0)),
            (input: 5, mod: 2, expectedResult: (standard: 1, nonNegative: 1)),
            (input: 7, mod: 5, expectedResult: (standard: 2, nonNegative: 2)),
            (input: 7, mod: -5, expectedResult: (standard: 2, nonNegative: 2)),
            (input: -7, mod: 5, expectedResult: (standard: -2, nonNegative: 3)),
            (input: -7, mod: -5, expectedResult: (standard: -2, nonNegative: 3)),
        ] {
            XCTAssertEqual(
                try vector.input.modulo(vector.mod, nonNegative: false),
                vector.expectedResult.standard,
                "\(vector.input) (mod \(vector.mod))"
            )
            XCTAssertEqual(
                try vector.input.modulo(vector.mod, nonNegative: true),
                vector.expectedResult.nonNegative,
                "\(vector.input) (nnmod \(vector.mod))"
            )
        }
    }

    func testModularInverse() throws {
        typealias I = ArbitraryPrecisionInteger
        enum O {
            case ok(I)
            case throwsError
        }
        typealias Vector = (a: I, mod: I, expectedResult: O)
        for vector: Vector in [
            (a: 3, mod: 7, expectedResult: .ok(5)),
            (a: 10, mod: 17, expectedResult: .ok(12)),
            (a: 7, mod: 26, expectedResult: .ok(15)),
            (a: 7, mod: 7, expectedResult: .throwsError),
        ] {
            switch vector.expectedResult {
            case .ok(let expectedValue):
                XCTAssertEqual(
                    try vector.a.inverse(modulo: vector.mod),
                    expectedValue,
                    "inverse(\(vector.a), modulo: \(vector.mod))"
                )
            case .throwsError:
                XCTAssertThrowsError(
                    try vector.a.inverse(modulo: vector.mod),
                    "inverse(\(vector.a), modulo: \(vector.mod)"
                )
            }
        }
    }

    func testModularAddition() throws {
        typealias I = ArbitraryPrecisionInteger
        enum O {
            case ok(I)
            case throwsError
        }
        typealias Vector = (a: I, b: I, mod: I, expectedResult: O)
        for vector: Vector in [
            (a: 0, b: 0, mod: 0, expectedResult: .throwsError),
            (a: 0, b: 0, mod: 2, expectedResult: .ok(0)),
            (a: 1, b: 0, mod: 2, expectedResult: .ok(1)),
            (a: 0, b: 1, mod: 2, expectedResult: .ok(1)),
            (a: 1, b: 1, mod: 2, expectedResult: .ok(0)),
            (a: 4, b: 3, mod: 5, expectedResult: .ok(2)),
            (a: 4, b: 3, mod: -5, expectedResult: .ok(2)),
            (a: -4, b: -3, mod: 5, expectedResult: .ok(3)),
        ] {
            switch vector.expectedResult {
            case .ok(let expectedValue):
                XCTAssertEqual(
                    try vector.a.add(vector.b, modulo: vector.mod),
                    expectedValue,
                    "\(vector.a) + \(vector.b) (mod \(vector.mod))"
                )
            case .throwsError:
                XCTAssertThrowsError(
                    try vector.a.add(vector.b, modulo: vector.mod),
                    "\(vector.a) + \(vector.b) (mod \(vector.mod))"
                )
            }
        }
    }

    func testModularSubtraction() throws {
        typealias I = ArbitraryPrecisionInteger
        enum O {
            case ok(I)
            case throwsError
        }
        typealias Vector = (a: I, b: I, mod: I, expectedResult: O)
        for vector: Vector in [
            (a: 0, b: 0, mod: 0, expectedResult: .throwsError),
            (a: 0, b: 0, mod: 2, expectedResult: .ok(0)),
            (a: 1, b: 0, mod: 2, expectedResult: .ok(1)),
            (a: 0, b: 1, mod: 2, expectedResult: .ok(1)),
            (a: 1, b: 1, mod: 2, expectedResult: .ok(0)),
            (a: 4, b: 3, mod: 5, expectedResult: .ok(1)),
            (a: 3, b: 4, mod: 5, expectedResult: .ok(4)),
            (a: 3, b: 4, mod: -5, expectedResult: .ok(4)),
            (a: -3, b: 4, mod: 5, expectedResult: .ok(3)),
            (a: 3, b: -4, mod: 5, expectedResult: .ok(2)),
        ] {
            switch vector.expectedResult {
            case .ok(let expectedValue):
                XCTAssertEqual(
                    try vector.a.sub(vector.b, modulo: vector.mod),
                    expectedValue,
                    "\(vector.a) - \(vector.b) (mod \(vector.mod))"
                )
            case .throwsError:
                XCTAssertThrowsError(
                    try vector.a.sub(vector.b, modulo: vector.mod),
                    "\(vector.a) - \(vector.b) (mod \(vector.mod))"
                )
            }
        }
    }

    func testModularMultiplication() throws {
        typealias I = ArbitraryPrecisionInteger
        enum O {
            case ok(I)
            case throwsError
        }
        typealias Vector = (a: I, b: I, mod: I, expectedResult: O)
        for vector: Vector in [
            (a: 0, b: 0, mod: 0, expectedResult: .throwsError),
            (a: 0, b: 0, mod: 2, expectedResult: .ok(0)),
            (a: 1, b: 0, mod: 2, expectedResult: .ok(0)),
            (a: 0, b: 1, mod: 2, expectedResult: .ok(0)),
            (a: 1, b: 1, mod: 2, expectedResult: .ok(1)),
            (a: 4, b: 3, mod: 5, expectedResult: .ok(2)),
            (a: 4, b: 3, mod: -5, expectedResult: .ok(2)),
            (a: -4, b: -3, mod: 5, expectedResult: .ok(2)),
        ] {
            switch vector.expectedResult {
            case .ok(let expectedValue):
                XCTAssertEqual(
                    try vector.a.mul(vector.b, modulo: vector.mod),
                    expectedValue,
                    "\(vector.a) × \(vector.b) (mod \(vector.mod))"
                )
            case .throwsError:
                XCTAssertThrowsError(
                    try vector.a.mul(vector.b, modulo: vector.mod),
                    "\(vector.a) × \(vector.b) (mod \(vector.mod))"
                )
            }
        }
    }
}
