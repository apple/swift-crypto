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
    /// A Distinguished Encoding Rules (DER) encoded representation of the private key in PKCS#8 format.
    public var pkcs8DERRepresentation: Data {
        self.derRepresentation
    }
}

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension Curve25519.KeyAgreement.PrivateKey {
    /// A Distinguished Encoding Rules (DER) encoded representation of the private key in PKCS#8 format.
    public var pkcs8DERRepresentation: Data {
        self.derRepresentation
    }
}

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension P256.Signing.PrivateKey {
    /// A Distinguished Encoding Rules (DER) encoded representation of the private key in PKCS#8 format.
    ///
    /// This property provides the same output as the existing `derRepresentation` property,
    /// which already conforms to the PKCS#8 standard.
    public var pkcs8DERRepresentation: Data {
        self.derRepresentation
    }
}

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension P384.Signing.PrivateKey {
    /// A Distinguished Encoding Rules (DER) encoded representation of the private key in PKCS#8 format.
    ///
    /// This property provides the same output as the existing `derRepresentation` property,
    /// which already conforms to the PKCS#8 standard.
    public var pkcs8DERRepresentation: Data {
        self.derRepresentation
    }
}

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension P521.Signing.PrivateKey {
    /// A Distinguished Encoding Rules (DER) encoded representation of the private key in PKCS#8 format.
    ///
    /// This property provides the same output as the existing `derRepresentation` property,
    /// which already conforms to the PKCS#8 standard.
    public var pkcs8DERRepresentation: Data {
        self.derRepresentation
    }
}
