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
import Crypto
@testable import CryptoExtras
import XCTest

struct HashToCurveTestVectorCurvePoint: Codable {
    let x: String
    let y: String

    var rawRepresentation: Data {
        return try! Data(hexString: String(x.dropFirst(2))) + Data(hexString: String(y.dropFirst(2)))
    }
}

struct HashToCurveTestVectorFile: Codable {
    let dst: String
    let vectors: [HashToCurveTestVector]
}

struct HashToCurveTestVector: Codable {
    let P: HashToCurveTestVectorCurvePoint
    let msg: String
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
class HashToCurveTests: XCTestCase {

    func testVector<C: SupportedCurveDetailsImpl>(vectorFileName file: String, with h2c: HashToCurveImpl<C>.Type) throws {
        #if CRYPTO_IN_SWIFTPM
        let bundle = Bundle.module
        #else
        let bundle = Bundle(for: type(of: self))
        #endif
        let fileURL = bundle.url(forResource: file, withExtension: "json")

        let data = try Data(contentsOf: fileURL!)
        let decoder = JSONDecoder()
        let testVectorFile = try decoder.decode(HashToCurveTestVectorFile.self, from: data)

        let dst = testVectorFile.dst

        for vector in testVectorFile.vectors {
            let msg = vector.msg.data(using: .ascii)!

            let point = h2c.hashToGroup(msg, domainSeparationString: Data(dst.utf8))

            XCTAssert(point.oprfRepresentation.hexString.dropFirst(2) == vector.P.x.dropFirst(2))
        }
    }

    func testVectors() throws {
        try testVector(vectorFileName: "P256_XMD-SHA-256_SSWU_RO_", with: HashToCurveImpl<P256>.self)
        try testVector(vectorFileName: "P384_XMD-SHA-384_SSWU_RO_", with: HashToCurveImpl<P384>.self)
//        try testVector(vectorFileName: "P521_XMD-SHA-512_SSWU_RO_", with: HashToCurveImpl<P521>.self)
    }

    func testH2F() throws {
        let data = try! Data(hexString: "436f6e746578742d564f50524630372d00000300097465737420696e666f")
        let dst = try! Data(hexString: "48617368546f5363616c61722d564f50524630372d000003")

        let scalar = try HashToField<P256>.hashToField(data,
                                                  outputElementCount: 1,
                                                  dst: dst,
                                                        outputSize: 48, reductionIsModOrder: false).first!

        let tv = try! Data(hexString: "5561bc4e7322a640b2ff6cb6aad96d1021f423233b858343caefa05abde7ef85")
        XCTAssert(scalar.rawRepresentation == tv)
    }

    func testExpandMessageXMD() throws {
        let dst = "QUUX-V01-CS02-with-expander".data(using: .ascii)!
        var msg = "".data(using: .ascii)!
        var uniformBytes = try Data(hexString: "f659819a6473c1835b25ea59e3d38914c98b374f0970b7e4c92181df928fca88")

        try XCTAssert(uniformBytes == HashToField<P256>.expandMessageXMD(msg, DST: dst, outputByteCount: 32))

        msg = "abc".data(using: .ascii)!
        uniformBytes = try Data(hexString: "1c38f7c211ef233367b2420d04798fa4698080a8901021a795a1151775fe4da7")

        try XCTAssert(uniformBytes == HashToField<P256>.expandMessageXMD(msg, DST: dst, outputByteCount: 32))

        msg = "abcdef0123456789".data(using: .ascii)!
        uniformBytes = try Data(hexString: "8f7e7b66791f0da0dbb5ec7c22ec637f79758c0a48170bfb7c4611bd304ece89")

        try XCTAssert(uniformBytes == HashToField<P256>.expandMessageXMD(msg, DST: dst, outputByteCount: 32))

        msg = "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".data(using: .ascii)!
        uniformBytes = try Data(hexString: "396962db47f749ec3b5042ce2452b619607f27fd3939ece2746a7614fb83a1d097f554df3927b084e55de92c7871430d6b95c2a13896d8a33bc48587b1f66d21b128a1a8240d5b0c26dfe795a1a842a0807bb148b77c2ef82ed4b6c9f7fcb732e7f94466c8b51e52bf378fba044a31f5cb44583a892f5969dcd73b3fa128816e")

        try XCTAssert(uniformBytes == HashToField<P256>.expandMessageXMD(msg, DST: dst, outputByteCount: 128))
    }

    func testScalarSerialization() throws {
        let serialized = try Data(hexString: "afe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a537220af1")

        let scalar = try GroupImpl<P256>.Scalar(bytes: serialized)

        XCTAssertEqual(scalar.rawRepresentation, serialized)
    }

    func testHash2Field() throws {
        let dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_".data(using: .ascii)!
        let msg = "abc".data(using: .ascii)!

        let elements = try HashToField<P256>.hashToField(msg, outputElementCount: 2, dst: dst, outputSize: 48, reductionIsModOrder: true)

        let u0 = elements.first!
        let u1 = elements.last!

        XCTAssertEqual(u0.rawRepresentation.hexString, "afe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a537220af1")
        XCTAssertEqual(u1.rawRepresentation.hexString, "379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd69ce9e46e0")
    }
}
