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
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
#if CRYPTOKIT_STATIC_LIBRARY
@_exported import CryptoKit_Static
#else
@_exported import CryptoKit
#endif
#else
/// General cryptography errors used by CryptoKit.
public enum CryptoKitError: Error {
    /// The key size is incorrect.
    case incorrectKeySize
    /// The parameter size is incorrect.
    case incorrectParameterSize
    /// The authentication tag or signature is incorrect.
    case authenticationFailure
    /// The underlying corecrypto library is unable to complete the requested
    /// action.
    case underlyingCoreCryptoError(error: Int32)
    /// The framework can't wrap the specified key.
    case wrapFailure
    /// The framework can't unwrap the specified key.
    case unwrapFailure
    /// The parameter is invalid.
    case invalidParameter
}

extension CryptoKitError: Equatable, Hashable {}

/// Errors from decoding ASN.1 content.
public enum CryptoKitASN1Error: Equatable, Error, Hashable {
    /// The ASN.1 tag for this field is invalid or unsupported.
    case invalidFieldIdentifier

    /// The ASN.1 tag for the parsed field doesn’t match the required format.
    case unexpectedFieldType

    /// An ASN.1 object identifier is invalid.
    case invalidObjectIdentifier

    /// The format of the parsed ASN.1 object doesn’t match the format required
    /// for the data type being decoded.
    case invalidASN1Object

    /// An ASN.1 integer doesn’t use the minimum number of bytes for its
    /// encoding.
    case invalidASN1IntegerEncoding

    /// An ASN.1 field is truncated.
    case truncatedASN1Field

    /// The encoding used for the field length is unsupported.
    case unsupportedFieldLength

    /// The string doesn’t parse as a PEM document.
    case invalidPEMDocument
}
#endif
