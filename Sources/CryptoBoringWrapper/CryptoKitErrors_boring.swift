//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CCryptoBoringSSL

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum CryptoBoringWrapperError: Error {
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CryptoBoringWrapperError {
    /// A helper function that packs the value of `ERR_get_error` into the internal error field.
    @usableFromInline
    package static func internalBoringSSLError() -> CryptoBoringWrapperError {
        .underlyingCoreCryptoError(error: Int32(bitPattern: CCryptoBoringSSL_ERR_get_error()))
    }
}
