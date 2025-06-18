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
extension Bool: ASN1ImplicitlyTaggable {
    static var defaultIdentifier: ASN1.ASN1Identifier {
        .boolean
    }

    init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
        guard node.identifier == identifier else {
            throw error(CryptoKitASN1Error.invalidASN1Object)
        }

        guard case .primitive(let bytes) = node.content, bytes.count == 1 else {
            throw error(CryptoKitASN1Error.invalidASN1Object)
        }

        switch bytes[bytes.startIndex] {
        case 0:
            // Boolean false
            self = false
        case 0xff:
            // Boolean true in DER
            self = true
        default:
            // If we come to support BER then these values are all "true" as well.
            throw error(CryptoKitASN1Error.invalidASN1Object)
        }
    }

    func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
        try coder.appendPrimitiveNode(identifier: identifier) { bytes in
            if self {
                bytes.append(0xff)
            } else {
                bytes.append(0)
            }
        }
    }
}

#endif // Linux or !SwiftPM
