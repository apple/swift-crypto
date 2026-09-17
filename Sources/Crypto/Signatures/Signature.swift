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

protocol SignatureVerification {
    func verifySignature(signature: Data, data: Data) throws(CryptoKitMetaError) -> Bool
}

protocol DigestSigner {
    associatedtype Signature
    func signature<D: Digest>(for digest: D) throws(CryptoKitMetaError) -> Signature
}

protocol Signer {
    associatedtype Signature
    func signature<D: DataProtocol>(for data: D) throws(CryptoKitMetaError) -> Signature
}
#endif // canImport(CryptoKit)
