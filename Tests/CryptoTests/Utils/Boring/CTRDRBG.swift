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
#if CRYPTO_IN_SWIFTPM && CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
@_implementationOnly import CCryptoBoringSSL
import Crypto

/// AES-CTR DRBG
final class Drbg {
    private let state: OpaquePointer

    init(_ seed: Data) throws {
        guard seed.count == CTR_DRBG_ENTROPY_LEN else {
            throw CryptoKitError.incorrectParameterSize
        }
        self.state = seed.withUnsafeBytes {
            CCryptoBoringSSL_CTR_DRBG_new($0.baseAddress, nil, 0)!
        }
    }

    func initializeWithRandomBytes(_ buffer: UnsafeMutableRawBufferPointer, count: Int) {
        guard count > 0 else {
            return
        }

        precondition(count <= buffer.count)

        let rc = CCryptoBoringSSL_CTR_DRBG_generate(
            self.state,
            buffer.baseAddress,
            buffer.count,
            nil,
            0
        )
        precondition(rc == 1)
    }

    var detRngPtr: Self { self }
}

extension UnsafeMutableRawBufferPointer {
    func initializeWithRandomBytes(count: Int, ccrngState: Drbg) {
        ccrngState.initializeWithRandomBytes(self, count: count)
    }
}

extension SymmetricKey {
    var dataRepresentation: Data {
        self.withUnsafeBytes { ptr in
            Data(ptr)
        }
    }
}

extension SymmetricKey {
    static func == (lhs: SymmetricKey, rhs: Data) -> Bool {
        lhs.dataRepresentation == rhs
    }
}

#endif  // CRYPTO_IN_SWIFTPM
