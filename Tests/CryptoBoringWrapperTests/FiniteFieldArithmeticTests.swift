//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
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

final class FiniteFieldArithmeticTests: XCTestCase {
    func testResidue() throws {
        let ff = try FiniteFieldArithmeticContext(fieldSize: 3)
        XCTAssertEqual(try ff.residue(-4), 2)
        XCTAssertEqual(try ff.residue(-3), 0)
        XCTAssertEqual(try ff.residue(-2), 1)
        XCTAssertEqual(try ff.residue(-1), 2)
        XCTAssertEqual(try ff.residue(+0), 0)
        XCTAssertEqual(try ff.residue(+1), 1)
        XCTAssertEqual(try ff.residue(+2), 2)
        XCTAssertEqual(try ff.residue(+3), 0)
        XCTAssertEqual(try ff.residue(+4), 1)
        XCTAssertEqual(try ff.residue(+5), 2)
        XCTAssertEqual(try ff.residue(+6), 0)
    }

    func testSquare() throws {
        let ff = try FiniteFieldArithmeticContext(fieldSize: 3)
        XCTAssertEqual(try ff.square(1), 1)
        XCTAssertEqual(try ff.square(2), 1)
        XCTAssertEqual(try ff.square(3), 0)
        XCTAssertEqual(try ff.square(4), 1)
        XCTAssertEqual(try ff.square(5), 1)
        XCTAssertEqual(try ff.square(-5), 1)
    }

    func testMultiply() throws {
        let ff = try FiniteFieldArithmeticContext(fieldSize: 3)
        XCTAssertEqual(try ff.multiply(1, 1), 1)
        XCTAssertEqual(try ff.multiply(2, 3), 0)
        XCTAssertEqual(try ff.multiply(4, 2), 2)
        XCTAssertEqual(try ff.multiply(4, -2), 1)
        XCTAssertEqual(try ff.multiply(-4, 2), 1)
        XCTAssertEqual(try ff.multiply(-4, -2), 2)
    }

    func testAdd() throws {
        let ff = try FiniteFieldArithmeticContext(fieldSize: 3)
        XCTAssertEqual(try ff.add(1, 0), 1)
        XCTAssertEqual(try ff.add(1, 1), 2)
        XCTAssertEqual(try ff.add(1, 2), 0)
        XCTAssertEqual(try ff.add(1, 3), 1)
        XCTAssertEqual(try ff.add(-1, 3), 2)
    }

    func testSubtract() throws {
        let ff = try FiniteFieldArithmeticContext(fieldSize: 3)
        XCTAssertEqual(try ff.subtract(0, from: 1), 1)
        XCTAssertEqual(try ff.subtract(1, from: 1), 0)
        XCTAssertEqual(try ff.subtract(2, from: 1), 2)
        XCTAssertEqual(try ff.subtract(5, from: 22), 2)
    }

    func testPositiveSquareRoot() throws {
        let ff = try FiniteFieldArithmeticContext(fieldSize: 3)
        XCTAssertEqual(try ff.positiveSquareRoot(1), 1)
        XCTAssertEqual(try ff.positiveSquareRoot(4), 1)
        XCTAssertEqual(try ff.positiveSquareRoot(9), 0)
        XCTAssertEqual(try ff.positiveSquareRoot(16), 1)
        XCTAssertEqual(try ff.positiveSquareRoot(25), 1)
    }

    func testInverse() throws {
        let ff = try FiniteFieldArithmeticContext(fieldSize: 3)
        XCTAssertEqual(try ff.inverse(1), 1)
        XCTAssertEqual(try ff.inverse(2), 2)
        XCTAssertEqual(try ff.inverse(3), nil)
        XCTAssertEqual(try ff.inverse(4), 1)
        XCTAssertEqual(try ff.inverse(5), 2)
        XCTAssertEqual(try ff.inverse(6), nil)
        for i: Int64 in 1...100 {
            let integer = ArbitraryPrecisionInteger(integerLiteral: i)
            let inverse = try ff.inverse(integer)
            if i % 3 == 0 {
                XCTAssertNil(inverse)
            } else {
                XCTAssertEqual(try ff.multiply(integer, XCTUnwrap(inverse)), 1)
            }
        }
    }

    func testPow() throws {
        let m: ArbitraryPrecisionInteger = 7
        let ff = try FiniteFieldArithmeticContext(fieldSize: m)
        for (x, p, expectedResult): (ArbitraryPrecisionInteger, ArbitraryPrecisionInteger, ArbitraryPrecisionInteger)
            in [
                (1, 0, 1), (1, 1, 1), (1, 2, 1), (1, 3, 1),
                (2, 0, 1), (2, 1, 2), (2, 2, 4), (2, 3, 1),
                (3, 0, 1), (3, 1, 3), (3, 2, 2), (3, 3, 6),
                (5, 0, 1), (5, 1, 5), (5, 2, 4), (5, 3, 6),
                (7, 0, 1), (7, 1, 0), (7, 2, 0), (7, 3, 0),  // x = m
                (8, 0, 1), (8, 1, 1), (8, 2, 1), (8, 3, 1),  // x > m
            ]
        {
            let message = "\(x)^\(p) (mod \(m))"
            XCTAssertEqual(try ff.pow(x, p), expectedResult, message)
            if x < m {
                XCTAssertEqual(try ff.pow(secret: x, p), expectedResult, message)
                XCTAssertEqual(try ff.pow(secret: x, secret: p), expectedResult, message)
            } else {
                XCTAssertThrowsError(try ff.pow(secret: x, p), message) { error in
                    switch error as? CryptoBoringWrapperError {
                    case .incorrectParameterSize: break  // OK
                    default: XCTFail("Unexpected error: \(error)")
                    }
                }
            }
        }
    }
}
