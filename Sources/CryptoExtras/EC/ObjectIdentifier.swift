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

import SwiftASN1

extension ASN1ObjectIdentifier.AlgorithmIdentifier {
    // Identifies the key agreement algorithm X25519.
    //
    // This identifier is defined in RFC 8410
    static let idX25519: ASN1ObjectIdentifier = [1, 3, 101, 110]

    // Identifies the key agreement algorithm X448.
    //
    // This identifier is defined in RFC 8410
    static let idX448: ASN1ObjectIdentifier = [1, 3, 101, 111]

    // Identifies the signature algorithm Ed25519.
    //
    // This identifier is defined in RFC 8410
    static let idEd25519: ASN1ObjectIdentifier = [1, 3, 101, 112]

    // Identifies the signature algorithm Ed448.
    //
    // This identifier is defined in RFC 8410
    static let idEd448: ASN1ObjectIdentifier = [1, 3, 101, 113]
}
