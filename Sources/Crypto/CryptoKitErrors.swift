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
#if CRYPTOKIT_STATIC_LIBRARY
@_exported import CryptoKit_Static
#else
@_exported import CryptoKit
#endif
#else
/// General cryptography errors used by CryptoKit.
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
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
    @available(iOS 15.0, macOS 12.0, watchOS 8.0, tvOS 15.0, macCatalyst 15.0, *)
    case wrapFailure
    /// The framework can't unwrap the specified key.
    @available(iOS 15.0, macOS 12.0, watchOS 8.0, tvOS 15.0, macCatalyst 15.0, *)
    case unwrapFailure
    /// The parameter is invalid.
    #if !CRYPTOKIT_STATIC_LIBRARY
    @available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, *)
    #else // CRYPTOKIT_STATIC_LIBRARY
    @available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
    #endif
    case invalidParameter
}

@available(iOS 17.4, macOS 14.4, watchOS 10.4, tvOS 17.4, macCatalyst 17.4, *)
extension CryptoKitError: Equatable, Hashable {}

/// Errors from decoding ASN.1 content.
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, macCatalyst 14.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 14.0, macOS 10.13, watchOS 7.0, tvOS 14.0, macCatalyst 14.0, visionOS 1.0, *)
#endif
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

enum RSAPSSSPKIErrors: Error {
    case invalidPSSOID
    case missingParameters
    case incorrectHashFunction
    case incorrectMGF
    case missingMGFHashFunction
    case incorrectMGFHashFunction
    case invalidSaltLength
}

#if hasFeature(Embedded)
public struct RSAPSSSPKIError: Error {
    internal var error: RSAPSSSPKIErrors
}
#else
struct RSAPSSSPKIError: Error {
    internal var error: RSAPSSSPKIErrors
}
#endif

#if hasFeature(Embedded)
public enum CryptoKitMetaError: Error {
    case cryptoKitError(underlyingError: CryptoKitError)
    case asn1Error(underlyingError: CryptoKitASN1Error)
    case rsapssspkiError(underlyingError: RSAPSSSPKIError)
}

internal func error(_ error: CryptoKitError) -> CryptoKitMetaError {
    .cryptoKitError(underlyingError: error)
}
internal func error(_ error: CryptoKitASN1Error) -> CryptoKitMetaError {
    .asn1Error(underlyingError: error)
}
internal func error(_ error: RSAPSSSPKIErrors) -> CryptoKitMetaError {
    .rsapssspkiError(underlyingError: RSAPSSSPKIError(error: error))
}
#else /* !hasFeature(Embedded) */
public typealias CryptoKitMetaError = any Error
internal func error(_ error: CryptoKitError) -> CryptoKitError { error }
internal func error(_ error: CryptoKitASN1Error) -> CryptoKitASN1Error { error }
internal func error(_ error: RSAPSSSPKIErrors) -> RSAPSSSPKIErrors { error }
#endif

#endif
