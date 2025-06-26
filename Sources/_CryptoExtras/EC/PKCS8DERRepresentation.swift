//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import Foundation
import SwiftASN1

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension Curve25519.Signing.PrivateKey {
    public var pkcs8DERRepresentation: Data {
        let pkey = ASN1.PKCS8PrivateKey(algorithm: .ed25519, privateKey: Array(self.rawRepresentation))
        var serializer = DER.Serializer()

        // Serializing this key can't throw
        try! serializer.serialize(pkey)
        return Data(serializer.serializedBytes)
    }
}

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension Curve25519.KeyAgreement.PrivateKey {
    public var pkcs8DERRepresentation: Data {
        let pkey = ASN1.PKCS8PrivateKey(algorithm: .x25519, privateKey: Array(self.rawRepresentation))
        var serializer = DER.Serializer()

        // Serializing this key can't throw
        try! serializer.serialize(pkey)
        return Data(serializer.serializedBytes)
    }
}

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension P256.Signing.PrivateKey {
    public var pkcs8DERRepresentation: Data {
        self.derRepresentation
    }
}

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension P384.Signing.PrivateKey {
    public var pkcs8DERRepresentation: Data {
        self.derRepresentation
    }
}

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension P521.Signing.PrivateKey {
    public var pkcs8DERRepresentation: Data {
        self.derRepresentation
    }
}
