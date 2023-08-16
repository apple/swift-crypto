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

public enum CryptoBoringWrapperError: Error {
    case underlyingCoreCryptoError(error: Int32)
}

extension CryptoBoringWrapperError {
    /// A helper function that packs the value of `ERR_get_error` into the internal error field.
    @usableFromInline
    static func internalBoringSSLError() -> CryptoBoringWrapperError {
        return .underlyingCoreCryptoError(error: Int32(bitPattern: CCryptoBoringSSL_ERR_get_error()))
    }
}
