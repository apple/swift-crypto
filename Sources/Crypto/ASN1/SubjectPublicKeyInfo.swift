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
    struct SubjectPublicKeyInfo: ASN1ImplicitlyTaggable {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .sequence
        }

        var algorithmIdentifier: RFC5480AlgorithmIdentifier

        var key: ASN1.ASN1BitString

        init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            // The SPKI block looks like this:
            //
            // SubjectPublicKeyInfo  ::=  SEQUENCE  {
            //   algorithm         AlgorithmIdentifier,
            //   subjectPublicKey  BIT STRING
            // }
            self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
                let algorithmIdentifier = try ASN1.RFC5480AlgorithmIdentifier(asn1Encoded: &nodes)
                let key = try ASN1.ASN1BitString(asn1Encoded: &nodes)

                return SubjectPublicKeyInfo(algorithmIdentifier: algorithmIdentifier, key: key)
            }
        }

        private init(algorithmIdentifier: RFC5480AlgorithmIdentifier, key: ASN1.ASN1BitString) {
            self.algorithmIdentifier = algorithmIdentifier
            self.key = key
        }

        internal init(algorithmIdentifier: RFC5480AlgorithmIdentifier, key: [UInt8]) {
            self.algorithmIdentifier = algorithmIdentifier
            self.key = ASN1BitString(bytes: key[...])
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            try coder.appendConstructedNode(identifier: identifier) { coder in
                try coder.serialize(self.algorithmIdentifier)
                try coder.serialize(self.key)
            }
        }
    }

    struct RFC5480AlgorithmIdentifier: ASN1ImplicitlyTaggable, Hashable {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .sequence
        }

        var algorithm: ASN1.ASN1ObjectIdentifier

        var parameters: ASN1.ASN1Any?

        init(algorithm: ASN1.ASN1ObjectIdentifier, parameters: ASN1.ASN1Any?) {
            self.algorithm = algorithm
            self.parameters = parameters
        }

        init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            // The AlgorithmIdentifier block looks like this.
            //
            // AlgorithmIdentifier  ::=  SEQUENCE  {
            //   algorithm   OBJECT IDENTIFIER,
            //   parameters  ANY DEFINED BY algorithm OPTIONAL
            // }
            //
            // ECParameters ::= CHOICE {
            //   namedCurve         OBJECT IDENTIFIER
            //   -- implicitCurve   NULL
            //   -- specifiedCurve  SpecifiedECDomain
            // }
            //
            // We don't bother with helpers: we just try to decode it directly.
            self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
                let algorithmOID = try ASN1.ASN1ObjectIdentifier(asn1Encoded: &nodes)

                let parameters = nodes.next().map { ASN1.ASN1Any(asn1Encoded: $0) }

                return .init(algorithm: algorithmOID, parameters: parameters)
            }
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            try coder.appendConstructedNode(identifier: identifier) { coder in
                try coder.serialize(self.algorithm)
                if let parameters = self.parameters {
                    try coder.serialize(parameters)
                }
            }
        }
    }
}

// MARK: Algorithm Identifier Statics
extension ASN1.RFC5480AlgorithmIdentifier {
    static let ecdsaP256 = ASN1.RFC5480AlgorithmIdentifier(algorithm: .AlgorithmIdentifier.idEcPublicKey,
                                                           parameters: try! .init(erasing: ASN1.ASN1ObjectIdentifier.NamedCurves.secp256r1))

    static let ecdsaP384 = ASN1.RFC5480AlgorithmIdentifier(algorithm: .AlgorithmIdentifier.idEcPublicKey,
                                                           parameters: try! .init(erasing: ASN1.ASN1ObjectIdentifier.NamedCurves.secp384r1))

    static let ecdsaP521 = ASN1.RFC5480AlgorithmIdentifier(algorithm: .AlgorithmIdentifier.idEcPublicKey,
                                                           parameters: try! .init(erasing: ASN1.ASN1ObjectIdentifier.NamedCurves.secp521r1))
}

#endif // Linux or !SwiftPM
