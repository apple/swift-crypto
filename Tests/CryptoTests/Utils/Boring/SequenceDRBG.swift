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
#if canImport(CryptoKit)
@_exported import CryptoKit
#else
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
@_implementationOnly import CCryptoBoringSSL
import Crypto

/// Sequence DRBG
final class SequenceDrbg {
    let state: [UInt8]

    init(_ seed: Data) throws {
        self.state = Array(seed)
    }

    var detRngPtr: Self { self }
}

#endif  // canImport(CryptoKit)
