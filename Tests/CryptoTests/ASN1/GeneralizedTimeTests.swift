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

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

final class GeneralizedTimeTests: XCTestCase {
    private func assertRoundTrips<ASN1Object: ASN1Parseable & ASN1Serializable & Equatable>(_ value: ASN1Object) throws {
        var serializer = ASN1.Serializer()
        try serializer.serialize(value)
        let parsed = try ASN1Object(asn1Encoded: serializer.serializedBytes)
        XCTAssertEqual(parsed, value)
    }

    func testSimpleGeneralizedTimeTestVectors() throws {
        // This is a small set of generalized time test vectors derived from the ASN.1 docs.
        // We store the byte payload here as a string.
        let vectors: [(String, ASN1.GeneralizedTime?)] = [
            // Valid representations
            ("19920521000000Z", try .init(year: 1992, month: 5, day: 21, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),
            ("19920622123421Z", try .init(year: 1992, month: 6, day: 22, hours: 12, minutes: 34, seconds: 21, fractionalSeconds: 0)),
            ("19920722132100.3Z", try .init(year: 1992, month: 7, day: 22, hours: 13, minutes: 21, seconds: 0, fractionalSeconds: 0.3)),
            ("19851106210627.3Z", try .init(year: 1985, month: 11, day: 6, hours: 21, minutes: 6, seconds: 27, fractionalSeconds: 0.3)),
            ("19851106210627.14159Z", try .init(year: 1985, month: 11, day: 6, hours: 21, minutes: 6, seconds: 27, fractionalSeconds: 0.14159)),
            ("20210131000000Z", try .init(year: 2021, month: 1, day: 31, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 31 days in January
            ("20210228000000Z", try .init(year: 2021, month: 2, day: 28, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 28 days in February 2021
            ("20200229000000Z", try .init(year: 2020, month: 2, day: 29, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 29 days in February 2020
            ("21000228000000Z", try .init(year: 2100, month: 2, day: 28, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 28 days in February 2100
            ("20000229000000Z", try .init(year: 2000, month: 2, day: 29, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 29 days in February 2000
            ("20210331000000Z", try .init(year: 2021, month: 3, day: 31, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 31 days in March
            ("20210430000000Z", try .init(year: 2021, month: 4, day: 30, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 30 days in April
            ("20210531000000Z", try .init(year: 2021, month: 5, day: 31, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 31 days in May
            ("20210630000000Z", try .init(year: 2021, month: 6, day: 30, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 30 days in June
            ("20210731000000Z", try .init(year: 2021, month: 7, day: 31, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 31 days in July
            ("20210831000000Z", try .init(year: 2021, month: 8, day: 31, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 31 days in August
            ("20210930000000Z", try .init(year: 2021, month: 9, day: 30, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 30 days in September
            ("20211031000000Z", try .init(year: 2021, month: 10, day: 31, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 31 days in October
            ("20211130000000Z", try .init(year: 2021, month: 11, day: 30, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 30 days in November
            ("20211231000000Z", try .init(year: 2021, month: 12, day: 31, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 0)),  // only 31 days in December

            // Invalid representations
            ("19920520240000Z", nil),  // midnight may not be 2400000
            ("19920622123421.0Z", nil),  // spurious trailing zeros
            ("19920722132100.30Z", nil),  // spurious trailing zeros
            ("19851106210627,3Z", nil),  // comma as decimal separator
            ("1985110621.14159Z", nil),  // missing minutes and seconds
            ("198511062106.14159Z", nil),  // missing seconds
            ("19851106210627.3", nil),  // missing trailing Z
            ("19851106210627.3-0500", nil),  // explicit time zone
            ("20211300000000Z", nil),  // there is no 13th month
            ("20210000000000Z", nil),  // there is no zeroth month
            ("20210100000000Z", nil),  // there is no zeroth day
            ("20210101000062Z", nil),  // 62nd second is not allowed
            ("20210101236000Z", nil),  // 60th minute is not allowed
            ("20210132000000Z", nil),  // only 31 days in January
            ("20210229000000Z", nil),  // only 28 days in February 2021
            ("20200230000000Z", nil),  // only 29 days in February 2020
            ("21000229000000Z", nil),  // only 28 days in February 2100
            ("20000230000000Z", nil),  // only 29 days in February 2000
            ("20210332000000Z", nil),  // only 31 days in March
            ("20210431000000Z", nil),  // only 30 days in April
            ("20210532000000Z", nil),  // only 31 days in May
            ("20210631000000Z", nil),  // only 30 days in June
            ("20210732000000Z", nil),  // only 31 days in July
            ("20210832000000Z", nil),  // only 31 days in August
            ("20210931000000Z", nil),  // only 30 days in September
            ("20211032000000Z", nil),  // only 31 days in October
            ("20211131000000Z", nil),  // only 30 days in November
            ("20211232000000Z", nil),  // only 31 days in December
            ("20200101000000.9223372036854775808Z", nil),  // Fractional part will overflow a 64-bit integer by adding
            ("20200101000000.92233720368547758071Z", nil)  // Fractional part will overflow a 64-bit integer by multiplication
        ]

        for (stringRepresentation, expectedResult) in vectors {
            var serialized = [UInt8]()
            serialized.append(ASN1.ASN1Identifier.generalizedTime.baseTag)
            serialized.append(UInt8(stringRepresentation.utf8.count))
            serialized.append(contentsOf: stringRepresentation.utf8)

            let result = try? ASN1.GeneralizedTime(asn1Encoded: serialized)
            XCTAssertEqual(result, expectedResult)

            if let expectedResult {
                try self.assertRoundTrips(expectedResult)
            }
        }
    }

    func testCreatingOutOfBoundsValuesViaInitFails() throws {
        func mustFail(_ code: @autoclosure () throws -> ASN1.GeneralizedTime) {
            XCTAssertThrowsError(try code())
        }

        mustFail(try .init(year: -1, month: 1, day: 1, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // Invalid year, negative
        mustFail(try .init(year: 2000, month: 0, day: 1, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // Invalid month, zero.
        mustFail(try .init(year: 2000, month: -1, day: 1, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // Invalid month, negative.
        mustFail(try .init(year: 2000, month: 13, day: 1, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // Invalid month, too large.
        mustFail(try .init(year: 2000, month: 1, day: 0, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // Invalid day, zero.
        mustFail(try .init(year: 2000, month: 1, day: -1, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // Invalid day, negative.
        mustFail(try .init(year: 2000, month: 1, day: 32, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 31 days in January
        mustFail(try .init(year: 2021, month: 2, day: 29, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 28 days in February 2021
        mustFail(try .init(year: 2020, month: 2, day: 30, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 29 days in February 2020
        mustFail(try .init(year: 2100, month: 2, day: 29, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 28 days in February 2100
        mustFail(try .init(year: 2000, month: 2, day: 30, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 29 days in February 2000
        mustFail(try .init(year: 2000, month: 3, day: 32, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 31 days in March
        mustFail(try .init(year: 2000, month: 4, day: 31, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 30 days in April
        mustFail(try .init(year: 2000, month: 5, day: 32, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 31 days in May
        mustFail(try .init(year: 2000, month: 6, day: 31, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 30 days in June
        mustFail(try .init(year: 2000, month: 7, day: 32, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 31 days in July
        mustFail(try .init(year: 2000, month: 8, day: 32, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 31 days in August
        mustFail(try .init(year: 2000, month: 9, day: 31, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 30 days in September
        mustFail(try .init(year: 2000, month: 10, day: 32, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 31 days in October
        mustFail(try .init(year: 2000, month: 11, day: 31, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 30 days in November
        mustFail(try .init(year: 2000, month: 11, day: 32, hours: 1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // only 31 days in December
        mustFail(try .init(year: 2000, month: 1, day: 1, hours: -1, minutes: 1, seconds: 1, fractionalSeconds: 0))  // Invalid hour, negative
        mustFail(try .init(year: 2000, month: 1, day: 1, hours: 24, minutes: 0, seconds: 0, fractionalSeconds: 0))  // Invalid hour, 24
        mustFail(try .init(year: 2000, month: 1, day: 1, hours: 0, minutes: -1, seconds: 1, fractionalSeconds: 0))  // Invalid minute, negative
        mustFail(try .init(year: 2000, month: 1, day: 1, hours: 0, minutes: 60, seconds: 0, fractionalSeconds: 0))  // Invalid minute, 60
        mustFail(try .init(year: 2000, month: 1, day: 1, hours: 0, minutes: 0, seconds: -1, fractionalSeconds: 0))  // Invalid second, negative
        mustFail(try .init(year: 2000, month: 1, day: 1, hours: 0, minutes: 0, seconds: 62, fractionalSeconds: 0))  // Invalid second, 62 (we allow some leap seconds)
        mustFail(try .init(year: 2000, month: 1, day: 1, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: -0.5))  // Invalid fractional seconds, negative
        mustFail(try .init(year: 2000, month: 1, day: 1, hours: 0, minutes: 0, seconds: 0, fractionalSeconds: 1.1))  // Invalid fractional seconds, greater than one
    }

    func testTruncatedRepresentationsRejected() throws {
        func mustNotDeserialize(_ stringRepresentation: Substring) {
            var serialized = [UInt8]()
            serialized.append(ASN1.ASN1Identifier.generalizedTime.baseTag)
            serialized.append(UInt8(stringRepresentation.utf8.count))
            serialized.append(contentsOf: stringRepresentation.utf8)

            XCTAssertThrowsError(try ASN1.GeneralizedTime(asn1Encoded: serialized))
        }

        func deserializes(_ stringRepresentation: Substring) {
            var serialized = [UInt8]()
            serialized.append(ASN1.ASN1Identifier.generalizedTime.baseTag)
            serialized.append(UInt8(stringRepresentation.utf8.count))
            serialized.append(contentsOf: stringRepresentation.utf8)

            XCTAssertNoThrow(try ASN1.GeneralizedTime(asn1Encoded: serialized))
        }

        // Anything that doesn't end up in a Z must fail to deserialize.
        let string = Substring("19851106210627.14159Z")
        for distance in 0..<string.count {
            let sliced = string.prefix(distance)
            mustNotDeserialize(sliced)
        }

        deserializes(string)

        // Adding some excess data should fail too.
        for junkByteCount in 1...string.count {
            let junked = string + string.prefix(junkByteCount)
            mustNotDeserialize(junked)
        }
    }

    func testRequiresAppropriateTag() throws {
        let rawValue = "19920521000000Z".utf8
        var invalidBytes = [UInt8]()
        invalidBytes.append(ASN1.ASN1Identifier.integer.baseTag)  // generalizedTime isn't an integer
        invalidBytes.append(UInt8(rawValue.count))
        invalidBytes.append(contentsOf: rawValue)

        XCTAssertThrowsError(try ASN1.GeneralizedTime(asn1Encoded: invalidBytes))
    }
}

#endif
