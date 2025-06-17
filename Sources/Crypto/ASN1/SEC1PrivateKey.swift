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
    // For private keys, SEC 1 uses:
    //
    // ECPrivateKey ::= SEQUENCE {
    //   version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    //   privateKey OCTET STRING,
    //   parameters [0] EXPLICIT ECDomainParameters OPTIONAL,
    //   publicKey [1] EXPLICIT BIT STRING OPTIONAL
    // }
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    struct SEC1PrivateKey: ASN1ImplicitlyTaggable {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            return .sequence
        }

        var algorithm: ASN1.RFC5480AlgorithmIdentifier?

        var privateKey: ASN1.ASN1OctetString

        var publicKey: ASN1.ASN1BitString?

        init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            self = try ASN1.sequence(rootNode, identifier: identifier) { nodes throws(CryptoKitMetaError) in
                let version = try Int(asn1Encoded: &nodes)
                guard 1 == version else {
                    throw error(CryptoKitASN1Error.invalidASN1Object)
                }

                let privateKey = try ASN1OctetString(asn1Encoded: &nodes)
                let parameters = try ASN1.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { node throws(CryptoKitMetaError) in
                    return try ASN1.ASN1ObjectIdentifier(asn1Encoded: node)
                }
                let publicKey = try ASN1.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { node throws(CryptoKitMetaError) in
                    return try ASN1.ASN1BitString(asn1Encoded: node)
                }

                return try .init(privateKey: privateKey, algorithm: parameters, publicKey: publicKey)
            }
        }

        private init(privateKey: ASN1.ASN1OctetString, algorithm: ASN1.ASN1ObjectIdentifier?, publicKey: ASN1.ASN1BitString?) throws(CryptoKitMetaError) {
            self.privateKey = privateKey
            self.publicKey = publicKey
            self.algorithm = try algorithm.map { algorithmOID throws(CryptoKitMetaError) in
                switch algorithmOID {
                case ASN1ObjectIdentifier.NamedCurves.secp256r1:
                    return .ecdsaP256
                case ASN1ObjectIdentifier.NamedCurves.secp384r1:
                    return .ecdsaP384
                case ASN1ObjectIdentifier.NamedCurves.secp521r1:
                    return .ecdsaP521
                default:
                    throw error(CryptoKitASN1Error.invalidASN1Object)
                }
            }
        }

        init(privateKey: [UInt8], algorithm: RFC5480AlgorithmIdentifier?, publicKey: [UInt8]) {
            self.privateKey = ASN1OctetString(contentBytes: privateKey[...])
            self.algorithm = algorithm
            self.publicKey = ASN1BitString(bytes: publicKey[...])
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            try coder.appendConstructedNode(identifier: identifier) { coder throws(CryptoKitMetaError) in
                try coder.serialize(1)  // version
                try coder.serialize(self.privateKey)

                if let algorithm = self.algorithm {
                    let oid: ASN1.ASN1ObjectIdentifier
                    switch algorithm {
                    case .ecdsaP256:
                        oid = ASN1ObjectIdentifier.NamedCurves.secp256r1
                    case .ecdsaP384:
                        oid = ASN1ObjectIdentifier.NamedCurves.secp384r1
                    case .ecdsaP521:
                        oid = ASN1ObjectIdentifier.NamedCurves.secp521r1
                    default:
                        throw error(CryptoKitASN1Error.invalidASN1Object)
                    }

                    try coder.serialize(oid, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
                }

                if let publicKey = self.publicKey {
                    try coder.serialize(publicKey, explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
                }
            }
        }
    }
}

#endif // Linux or !SwiftPM
