//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Foundation
import XCTest
import Crypto
@testable import _CryptoExtras

fileprivate struct TestVector: Codable {
    var name, p, q, n, e, d, msg, msg_prefix, prepared_msg, salt, inv, blinded_msg, blind_sig, sig: String

    var parameters: _RSA.BlindSigning.Parameters<SHA384> {
        .init(
            padding: self.salt.count == 0 ? .PSSZERO : .PSS,
            preparation: self.msg == self.prepared_msg ? .identity : .randomized
        )
    }

    static func load(from fileURL: URL) throws -> [Self] {
        let json = try Data(contentsOf: fileURL)
        let decoder = JSONDecoder()
        return try decoder.decode([Self].self, from: json)
    }
}

final class TestRSABlindSigning: XCTestCase {
    func testAgainstRFC9474TestVectors() throws {
        let testVectors = try TestVector.load(from: URL(
            fileURLWithPath: "../_CryptoExtrasVectors/rfc9474.json",
            relativeTo: URL(fileURLWithPath: #file)
        ))

        // Security framework doesn't have the API we need to support the PSSZERO variants.
        #if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        let filteredTestVectors = testVectors.filter { $0.parameters.padding.backing != .pssZero }
        #else
        let filteredTestVectors = testVectors
        #endif

        for testVector in filteredTestVectors {
            // Prepare
            do {
                let message = try Data(hexString: testVector.msg)
                switch testVector.parameters.preparation {
                case .identity:
                    let preparedMessage = _RSA.BlindSigning.prepare(message, parameters: testVector.parameters)
                    XCTAssertEqual(Data(preparedMessage), message)
                case .randomized:
                    break  // Until we have SPI secure bytes.
                    let preparedMessage = _RSA.BlindSigning.prepare(message, parameters: testVector.parameters)
                    XCTAssertEqual(Data(preparedMessage.dropFirst(32)), message)
                }
            }

            // Blind
            do {
            }

            // BlindSign
            do {
                let privateKey = try _RSA.BlindSigning.PrivateKey(
                    nHexString: testVector.n,
                    eHexString: testVector.e,
                    dHexString: testVector.d,
                    pHexString: testVector.p,
                    qHexString: testVector.q
                )
                let blindedMessage = try Data(hexString: testVector.blinded_msg)
                let blindSignature = try privateKey.blindSignature(for: blindedMessage)
                XCTAssertEqual(
                    blindSignature.rawRepresentation.hexString,
                    try Data(hexString: testVector.blind_sig).hexString
                )
            }

            // Finalize
            do {
            }

            // Verification
            do {
                let publicKey = try _RSA.BlindSigning.PublicKey(nHexString: testVector.n, eHexString: testVector.e)
                let signature = try _RSA.Signing.RSASignature(rawRepresentation: Data(hexString: testVector.sig))
                let preparedMessage = try Data(hexString: testVector.prepared_msg)
                XCTAssert(publicKey.isValidSignature(signature, for: preparedMessage, parameters: testVector.parameters))
            }
        }
    }
}
