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
/// Errors thrown in CryptoKit
/// - incorrectKeySize: A key is being deserialized with an incorrect key size.
/// - incorrectParameterSize: The number of bytes passed for a given argument is incorrect.
/// - authenticationFailure: The authentication tag or signature is incorrect.
/// - underlyingCoreCryptoError: An unexpected error at a lower-level occured.
/// - wrapFailure: Failed to wrap key
/// - unwrapFailure: Failed to unwrap key
public enum CryptoKitError: Error {
    case incorrectKeySize
    case incorrectParameterSize
    case authenticationFailure
    case underlyingCoreCryptoError(error: Int32)
    case wrapFailure
    case unwrapFailure
}

/// Errors encountered when parsing ASN.1 formatted keys.
public enum CryptoKitASN1Error: Error {
    /// The ASN.1 tag for this field is invalid or unsupported.
    case invalidFieldIdentifier

    /// The ASN.1 tag for the parsed field does not match the required format.
    case unexpectedFieldType

    /// An invalid ASN.1 object identifier was encountered.
    case invalidObjectIdentifier

    /// The format of the parsed ASN.1 object does not match the format required for the data type
    /// being decoded.
    case invalidASN1Object

    /// An ASN.1 integer was decoded that does not use the minimum number of bytes for its encoding.
    case invalidASN1IntegerEncoding

    /// An ASN.1 field was truncated and could not be decoded.
    case truncatedASN1Field

    /// The encoding used for the field length is not supported.
    case unsupportedFieldLength

    /// It was not possible to parse a string as a PEM document.
    case invalidPEMDocument
}
#endif
