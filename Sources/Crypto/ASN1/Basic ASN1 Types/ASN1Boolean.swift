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

extension Bool: ASN1ImplicitlyTaggable {
    static var defaultIdentifier: ASN1.ASN1Identifier {
        .boolean
    }

    init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        guard node.identifier == identifier else {
            throw CryptoKitASN1Error.invalidASN1Object
        }

        guard case .primitive(let bytes) = node.content, bytes.count == 1 else {
            throw CryptoKitASN1Error.invalidASN1Object
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
            throw CryptoKitASN1Error.invalidASN1Object
        }
    }

    func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        coder.appendPrimitiveNode(identifier: identifier) { bytes in
            if self {
                bytes.append(0xff)
            } else {
                bytes.append(0)
            }
        }
    }
}

#endif // Linux or !SwiftPM
