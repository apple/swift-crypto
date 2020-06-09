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
import Foundation

protocol SignatureVerification {
    func verifySignature(signature: Data, data: Data) throws -> Bool
}

protocol DigestSigner {
    associatedtype Signature
    func signature<D: Digest>(for digest: D) throws -> Signature
}

protocol Signer {
    associatedtype Signature
    func signature<D: DataProtocol>(for data: D) throws -> Signature
}
#endif // Linux or !SwiftPM
