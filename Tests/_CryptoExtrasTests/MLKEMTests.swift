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

@testable import _CryptoExtras

@available(macOS 14.0, *)
final class MLKEMTests: XCTestCase {
    func testMLKEM_768() throws {
        // Generate a key pair
        let privateKey = MLKEM.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Serialize and deserialize the private key
        let seed = privateKey.seed
        let privateKey2 = try MLKEM.PrivateKey(seed: seed)
        XCTAssertEqual(privateKey.seed, privateKey2.seed)
        
        // Serialize and deserialize the public key
        let publicKeyBytes = publicKey.rawRepresentation
        var modifiedPublicKeyBytes = publicKeyBytes
        modifiedPublicKeyBytes[0] = 0xff
        modifiedPublicKeyBytes[1] = 0xff
        // Parsing should fail because the first coefficient is >= kPrime;
        XCTAssertThrowsError(try MLKEM.PublicKey(rawRepresentation: modifiedPublicKeyBytes))
        
        let publicKey2 = try MLKEM.PublicKey(rawRepresentation: publicKeyBytes)
        XCTAssertEqual(publicKeyBytes, publicKey2.rawRepresentation)
        
        // Ensure public key derived from private key matches the original public key
        let derivedPublicKey = privateKey.publicKey
        XCTAssertEqual(publicKeyBytes, derivedPublicKey.rawRepresentation)
        
        // Serialize and deserialize the private key with modifications
        var modifiedSeed = privateKey.seed
        modifiedSeed[0] = 0xff
        XCTAssertNotEqual(
            try MLKEM.PrivateKey(seed: modifiedSeed).publicKey.rawRepresentation,
            publicKeyBytes
        )
        
        // Encapsulation and decapsulation
        let encapsulationResult = publicKey.encapsulate()
        let sharedSecret1 = encapsulationResult.sharedSecret
        let ciphertext = encapsulationResult.encapsulated
        
        let sharedSecret2 = try privateKey.decapsulate(ciphertext)
        XCTAssertEqual(sharedSecret1, sharedSecret2)
    }
}