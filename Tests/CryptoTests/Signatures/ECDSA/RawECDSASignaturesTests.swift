//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import XCTest

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

typealias TestVector = (publicKey: Data, privateKey: Data, rs: rAndS)
typealias rAndS = (r: Data, s: Data)

func testVectorForCurve<S: NISTSigning>(curve: S.Type, file: StaticString = #file, line: UInt = #line) throws -> TestVector {
    switch S.self {
    case is P256.Signing.Type:
        do {
            return TestVector(
                publicKey: try orFail(file: file, line: line) { try Data(hexString: "2442a5cc0ecd015fa3ca31dc8e2bbc70bf42d60cbca20085e0822cb04235e9706fc98bd7e50211a4a27102fa3549df79ebcb4bf246b80945cddfe7d509bbfd7d") },
                privateKey: try orFail(file: file, line: line) { try Data(hexString: "dc51d3866a15bacde33d96f992fca99da7e6ef0934e7097559c27f1614c88a7f") },
                rs: rAndS(r: try orFail(file: file, line: line) { try Data(hexString: "cb28e0999b9c7715fd0a80d8e47a77079716cbbf917dd72e97566ea1c066957c") },
                          s: try orFail(file: file, line: line) { try Data(hexString: "86fa3bb4e26cad5bf90b7f81899256ce7594bb1ea0c89212748bff3b3d5b0315") }))
    }
    case is P384.Signing.Type: do {
        return TestVector(
            publicKey: try orFail(file: file, line: line) { try Data(hexString: "96281bf8dd5e0525ca049c048d345d3082968d10fedf5c5aca0c64e6465a97ea5ce10c9dfec21797415710721f437922447688ba94708eb6e2e4d59f6ab6d7edff9301d249fe49c33096655f5d502fad3d383b91c5e7edaa2b714cc99d5743ca") },
            privateKey: try orFail(file: file, line: line) { try Data(hexString: "0beb646634ba87735d77ae4809a0ebea865535de4c1e1dcb692e84708e81a5af62e528c38b2a81b35309668d73524d9f") },
            rs: rAndS(r: try orFail(file: file, line: line) { try Data(hexString: "fb017b914e29149432d8bac29a514640b46f53ddab2c69948084e2930f1c8f7e08e07c9c63f2d21a07dcb56a6af56eb3") },
                      s: try orFail(file: file, line: line) { try Data(hexString: "b263a1305e057f984d38726a1b46874109f417bca112674c528262a40a629af1cbb9f516ce0fa7d2ff630863a00e8b9f") }))
        }
    case is P521.Signing.Type: do {
        return TestVector(
            publicKey: try orFail(file: file, line: line) { try Data(hexString: "0151518f1af0f563517edd5485190df95a4bf57b5cba4cf2a9a3f6474725a35f7afe0a6ddeb8bedbcd6a197e592d40188901cecd650699c9b5e456aea5add19052a8006f3b142ea1bfff7e2837ad44c9e4ff6d2d34c73184bbad90026dd5e6e85317d9df45cad7803c6c20035b2f3ff63aff4e1ba64d1c077577da3f4286c58f0aeae643") },
            privateKey: try orFail(file: file, line: line) { try Data(hexString: "0065fda3409451dcab0a0ead45495112a3d813c17bfd34bdf8c1209d7df5849120597779060a7ff9d704adf78b570ffad6f062e95c7e0c5d5481c5b153b48b375fa1") },
            rs: rAndS(r: try orFail(file: file, line: line) { try Data(hexString: "0154fd3836af92d0dca57dd5341d3053988534fde8318fc6aaaab68e2e6f4339b19f2f281a7e0b22c269d93cf8794a9278880ed7dbb8d9362caeacee544320552251") },
                      s: try orFail(file: file, line: line) { try Data(hexString: "017705a7030290d1ceb605a9a1bb03ff9cdd521e87a696ec926c8c10c8362df4975367101f67d1cf9bccbf2f3d239534fa509e70aac851ae01aac68d62f866472660") }))
        }
    default:
        XCTFail("Unhandled type: \(S.self)")
        throw TestError.unhandled
    }
}

class RawECDSASignaturesTests: XCTestCase {
    func testForCurve<S: NISTSigning>(curve: S.Type, file: StaticString = #file, line: UInt = #line) throws {
        let msg = try unwrap("abc".data(using: .utf8), file: file, line: line)
        // We check that the test message is correctly encoded.
        XCTAssertEqual(msg, try Data(hexString: "616263"), file: file, line: line)

        let tv = try orFail(file: file, line: line) { try testVectorForCurve(curve: curve) }

        let signature = try orFail(file: file, line: line) { try S.ECDSASignature(rawRepresentation: tv.rs.r + tv.rs.s) }

        let privateKey = try orFail(file: file, line: line) { try S.PrivateKey(rawRepresentation: tv.privateKey) }
        let publicKey = try orFail(file: file, line: line) { try S.PublicKey(rawRepresentation: tv.publicKey) }
        
        XCTAssertEqual(privateKey.rawRepresentation, tv.privateKey, file: file, line: line)
        XCTAssertEqual(privateKey.publicKey.rawRepresentation, tv.publicKey, file: file, line: line)

        let typedSignature = try unwrap(signature as? S.PublicKey.Signature, file: file, line: line)
        XCTAssert(publicKey.isValidSignature(typedSignature, for: msg), file: file, line: line)

        let privateKeySignature = try orFail { try privateKey.signature(for: msg) }
        let typedPrivateKeySignature = try unwrap(privateKeySignature as? S.PublicKey.Signature, file: file, line: line)
        XCTAssert(publicKey.isValidSignature(typedPrivateKeySignature, for: msg), file: file, line: line)
    }

    // Test Vectors from: https://tools.ietf.org/html/rfc4754#section-8
    func testRFC4753() throws {
        try orFail { try testForCurve(curve: P256.Signing.self) }
        try orFail { try testForCurve(curve: P384.Signing.self) }
        try orFail { try testForCurve(curve: P521.Signing.self) }
    }
}
#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM
