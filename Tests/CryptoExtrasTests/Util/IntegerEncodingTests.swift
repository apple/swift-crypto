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
@testable import CryptoExtras
import XCTest

final class IntegerEncodingTests: XCTestCase {
    func testIntegerDecoding() throws {
        func test<T: FixedWidthInteger>(
            decoding bytes: [UInt8],
            as: T.Type,
            expect expectedResult: Swift.Result<T, IntegerDecodingError>,
            file: StaticString = #filePath, line: UInt = #line
        ) {
            let actualResult = Swift.Result { try T(bigEndianBytes: bytes) }
            switch (actualResult, expectedResult) {
            case (.success(let actual), .success(let expected)):
                XCTAssertEqual(actual, expected, file: file, line: line)
            case (.success(let actual), .failure(let error)):
                XCTFail("Expected error: \(error), got \(actual)", file: file, line: line)
            case (.failure(let error), .success(let expected)):
                XCTFail("Decode failed; expected: \(expected), got error: \(error)", file: file, line: line)
            case (.failure(let actualError), .failure(let expectedError)):
                guard let typedError = actualError as? IntegerDecodingError else {
                    XCTFail("Expected error but not this one: \(actualError)", file: file, line: line)
                    return
                }
                XCTAssertEqual(typedError, expectedError, file: file, line: line)
            }
        }

        test(decoding: [0,0], as: UInt16.self, expect: .success(0))
        test(decoding: [0,1], as: UInt16.self, expect: .success(1))
        test(decoding: [1,0], as: UInt16.self, expect: .success(256))
        test(decoding: [1,1], as: UInt16.self, expect: .success(257))
        test(decoding: [0xff,0xff], as: UInt16.self, expect: .success(UInt16.max))

        test(decoding: [], as: UInt16.self, expect: .failure(.incorrectNumberOfBytes(expected: 2, actual: 0)))
        test(decoding: [0], as: UInt16.self, expect: .failure(.incorrectNumberOfBytes(expected: 2, actual: 1)))
        test(decoding: [0,0,0], as: UInt16.self, expect: .failure(.incorrectNumberOfBytes(expected: 2, actual: 3)))
        test(decoding: [0,0,0,0], as: UInt16.self, expect: .failure(.incorrectNumberOfBytes(expected: 2, actual: 4)))

        test(decoding: [0,0], as: Int16.self, expect: .success(0))
        test(decoding: [0,1], as: Int16.self, expect: .success(1))
        test(decoding: [1,0], as: Int16.self, expect: .success(256))
        test(decoding: [1,1], as: Int16.self, expect: .success(257))
        test(decoding: [0xff,0xff], as: Int16.self, expect: .success(-1))
        test(decoding: [0x80,0x00], as: Int16.self, expect: .success(Int16.min))
        test(decoding: [0x7f,0xff], as: Int16.self, expect: .success(Int16.max))

        test(decoding: [], as: Int16.self, expect: .failure(.incorrectNumberOfBytes(expected: 2, actual: 0)))
        test(decoding: [0], as: Int16.self, expect: .failure(.incorrectNumberOfBytes(expected: 2, actual: 1)))
        test(decoding: [0,0,0], as: Int16.self, expect: .failure(.incorrectNumberOfBytes(expected: 2, actual: 3)))
        test(decoding: [0,0,0,0], as: Int16.self, expect: .failure(.incorrectNumberOfBytes(expected: 2, actual: 4)))
    }

    func testIntegerEncoding() throws {
        func test<T: FixedWidthInteger>(encoding value: T, expect bytes: [UInt8], file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertEqual(value.bigEndianBytes, Data(bytes), file: file, line: line)
        }

        test(encoding: UInt16.zero, expect: [0,0])
        test(encoding: UInt16(1), expect: [0,1])
        test(encoding: UInt16(256), expect: [1,0])
        test(encoding: UInt16(257), expect: [1,1])
        test(encoding: UInt16.max, expect: [0xff,0xff])

        test(encoding: Int16.zero, expect: [0,0])
        test(encoding: Int16(1), expect: [0,1])
        test(encoding: Int16(256), expect: [1,0])
        test(encoding: Int16(257), expect: [1,1])
        test(encoding: Int16(-1), expect: [0xff,0xff])
        test(encoding: Int16.min, expect: [0x80,0x00])
        test(encoding: Int16.max, expect: [0x7f,0xff])
    }

    func testIntegerEncodingDataAppend() throws {
        var bytes = Data()

        bytes.append(bigEndianBytesOf: Int32(1))
        bytes.append(bigEndianBytesOf: Int16(2))
        bytes.append(bigEndianBytesOf: Int8(3))
        bytes.append(bigEndianBytesOf: Int64(4))

        XCTAssertEqual(bytes.hexString, Data([0,0,0,1] + [0,2] + [3] + [0,0,0,0,0,0,0,4]).hexString)
    }

    func testIntegerDecodingFromDataSubsequence() throws {
        let data = Data([0,0,0,1] + [0,2] + [3] + [0,0,0,0,0,0,0,4])

        var bytes = data[...]

        XCTAssertEqual(bytes.count, 15)

        XCTAssertEqual(try Int32(bigEndianBytes: bytes[..<bytes.startIndex.advanced(by: 4)]), 1)
        bytes.removeFirst(4)

        XCTAssertEqual(try Int16(bigEndianBytes: bytes[..<bytes.startIndex.advanced(by: 2)]), 2)
        bytes.removeFirst(2)

        XCTAssertEqual(try Int8(bigEndianBytes: bytes[..<bytes.startIndex.advanced(by: 1)]), 3)
        bytes.removeFirst(1)

        XCTAssertEqual(try Int64(bigEndianBytes: bytes[..<bytes.startIndex.advanced(by: 8)]), 4)
        bytes.removeFirst(8)

        XCTAssert(bytes.isEmpty)
    }

    func testIntegerDecodingUsingDataPopFirstK() throws {
        var bytes = Data([0,0,0,1] + [0,2] + [3] + [0,0,0,0,0,0,0,4])

        XCTAssertEqual(bytes.count, 15)

        XCTAssertEqual(try Int32(bigEndianBytes: bytes.popFirst(4)), 1)
        XCTAssertEqual(try Int16(bigEndianBytes: bytes.popFirst(2)), 2)
        XCTAssertEqual(try Int8(bigEndianBytes: bytes.popFirst(1)), 3)
        XCTAssertEqual(try Int64(bigEndianBytes: bytes.popFirst(8)), 4)

        XCTAssert(bytes.isEmpty)
    }

    func testIntegerDecodingUsingDataPopFirst() throws {
        var bytes = Data([0,0,0,1] + [0,2] + [3] + [0,0,0,0,0,0,0,4])

        XCTAssertEqual(bytes.count, 15)

        XCTAssertEqual(try bytes.popFirst(bigEndian: Int32.self), 1)
        XCTAssertEqual(try bytes.popFirst(bigEndian: Int16.self), 2)
        XCTAssertEqual(try bytes.popFirst(bigEndian: Int8.self), 3)
        XCTAssertEqual(try bytes.popFirst(bigEndian: Int64.self), 4)

        XCTAssert(bytes.isEmpty)
    }

    func testIntegerDecodingUsingDataPopFirstTooFewBytes() throws {
        var bytes = Data([0])

        XCTAssertThrowsError(try bytes.popFirst(bigEndian: Int16.self))
        XCTAssertThrowsError(try bytes.popFirst(bigEndian: Int32.self))
        XCTAssertThrowsError(try bytes.popFirst(bigEndian: Int64.self))
    }
}
