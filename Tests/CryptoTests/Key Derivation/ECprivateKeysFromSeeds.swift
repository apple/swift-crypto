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
import Foundation
import XCTest

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

extension CryptoKitError: Equatable {
    public static func == (lhs: CryptoKitError, rhs: CryptoKitError) -> Bool {
        switch (lhs, rhs) {
        case (.incorrectKeySize, .incorrectKeySize):
            return true
        case (.incorrectParameterSize, .incorrectParameterSize):
            return true
        case (.authenticationFailure, .authenticationFailure):
            return true
        case (.wrapFailure, .wrapFailure):
            return true
        case (.unwrapFailure, .unwrapFailure):
            return true
        case (.underlyingCoreCryptoError(let lhsError), .underlyingCoreCryptoError(let rhsError)):
            return lhsError == rhsError
        default:
            return false
        }
    }
}

#endif // Linux or !SwiftPM
