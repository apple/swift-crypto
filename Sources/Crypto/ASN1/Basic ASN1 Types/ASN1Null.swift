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

extension ASN1 {
    /// An ASN1 NULL represents nothing.
    struct ASN1Null: ASN1ImplicitlyTaggable, Hashable {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .null
        }

        init() { }

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            guard node.identifier == identifier, case .primitive(let content) = node.content else {
                throw CryptoKitASN1Error.unexpectedFieldType
            }

            guard content.count == 0 else {
                throw CryptoKitASN1Error.invalidASN1Object
            }
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) {
            coder.appendPrimitiveNode(identifier: identifier, { _ in })
        }
    }
}

#endif // Linux or !SwiftPM
