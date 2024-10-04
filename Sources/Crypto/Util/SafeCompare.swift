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
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
#if CRYPTOKIT_STATIC_LIBRARY
@_exported import CryptoKit_Static
#else
@_exported import CryptoKit
#endif
#else
#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
import SwiftSystem
#else
import Foundation
#endif

internal func safeCompare<LHS: ContiguousBytes, RHS: ContiguousBytes>(_ lhs: LHS, _ rhs: RHS) -> Bool {
    #if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
    return coreCryptoSafeCompare(lhs, rhs)
    #else
    return openSSLSafeCompare(lhs, rhs)
    #endif
}

#endif // Linux or !SwiftPM
