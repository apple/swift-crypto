//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CCryptoBoringSSL
import Crypto

extension CryptoKitError {
    /// A helper function that packs the value of `ERR_get_error` into the internal error field.
    @usableFromInline
    static func internalBoringSSLError() -> CryptoKitError {
        return .underlyingCoreCryptoError(error: Int32(bitPattern: CCryptoBoringSSL_ERR_get_error()))
    }
}

extension CryptoKitError {
    public var description: String {
        switch self {
        case .underlyingCoreCryptoError(error: let error):
            let errorCode = UInt32(bitPattern: error)
            let lib = String(cString: CCryptoBoringSSL_ERR_lib_error_string(errorCode))
            let reason = String(cString: CCryptoBoringSSL_ERR_reason_error_string(errorCode))
            return "lib: \(lib), reason: \(reason), code: \(errorCode)"
        case .incorrectKeySize: return "incorrectKeySize"
        case .incorrectParameterSize: return "incorrectParameterSize"
        case .authenticationFailure: return "authenticationFailure"
        case .wrapFailure: return "wrapFailure"
        case .unwrapFailure: return "unwrapFailure"
        case .invalidParameter: return "invalidParameter"
        @unknown default: return "unknown"
        }
    }
}

#if hasAttribute(retroactive)
extension CryptoKitError: @retroactive CustomStringConvertible {}
#else
extension CryptoKitError: CustomStringConvertible {}
#endif
