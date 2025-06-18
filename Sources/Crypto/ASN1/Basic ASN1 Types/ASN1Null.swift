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
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
import SwiftSystem
#else
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ASN1 {
    /// An ASN1 NULL represents nothing.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    struct ASN1Null: ASN1ImplicitlyTaggable, Hashable {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .null
        }

        init() { }

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            guard node.identifier == identifier, case .primitive(let content) = node.content else {
                throw error(CryptoKitASN1Error.unexpectedFieldType)
            }

            guard content.count == 0 else {
                throw error(CryptoKitASN1Error.invalidASN1Object)
            }
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            try coder.appendPrimitiveNode(identifier: identifier, { _ in })
        }
    }
}

#endif // Linux or !SwiftPM
