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
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
/// The Advanced Encryption Standard (AES)
public enum AES {
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
#endif // Linux or !SwiftPM
