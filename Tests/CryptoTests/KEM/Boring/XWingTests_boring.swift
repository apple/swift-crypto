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

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

extension XWingMLKEM768X25519.PrivateKey {
    static func generateWithRng(rngState: SequenceDrbg) throws -> Self {
        // We're going to generate a "random" seed.
        var seed: [UInt8] = []
        seed.reserveCapacity(32)

        for i in 0..<32 {
            seed.append(rngState.state[i % rngState.state.count])
        }

        return try Self(seedRepresentation: seed, publicKey: nil)
    }
}

extension XWingMLKEM768X25519.PublicKey {
    func encapsulateWithRng(rngState: SequenceDrbg) throws -> KEM.EncapsulationResult {
        // We're going to generate "random" entropy
        var seed: [UInt8] = []
        seed.reserveCapacity(64)

        for i in 0..<64 {
            seed.append(rngState.state[i % rngState.state.count])
        }

        return try self.impl.encapsulateWithOptionalEntropy(entropy: seed)
    }
}

#endif  // CRYPTO_IN_SWIFTPM
