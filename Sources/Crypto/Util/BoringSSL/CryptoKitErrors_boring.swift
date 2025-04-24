//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CryptoKitError {
    /// A helper function that packs the value of `ERR_get_error` into the internal error field.
    @usableFromInline
    static func internalBoringSSLError() -> CryptoKitError {
        .underlyingCoreCryptoError(error: Int32(bitPattern: CCryptoBoringSSL_ERR_get_error()))
    }
}
#endif  // CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
