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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension KEM {
    /// Errors that CryptoKit throws when it encounters problems in key encapsulation mechanism (KEM) operations.
    @nonexhaustive
    public enum Errors: Error {
        /// The public key CryptoKit receives when it initializes a key encapsulation operation doesn't match the expected value.
        case publicKeyMismatchDuringInitialization

        /// The seed value supplied for deriving a key isn't valid.
        case invalidSeed
    }
}

#endif // canImport(CryptoKit)
