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

#if canImport(CryptoKit)
@_exported import CryptoKit
#else
/// A container for Advanced Encryption Standard (AES) ciphers.
@nonexhaustive
public enum AES: Sendable {
    static let blockSizeByteCount = 16
}

extension AES {
    static func isValidKey(_ key: SymmetricKey) -> Bool {
        switch key.bitCount {
        case 128:
            return true
        case 192:
            return true
        case 256:
            return true
        default:
            return false
        }
    }
}
#endif // canImport(CryptoKit)
