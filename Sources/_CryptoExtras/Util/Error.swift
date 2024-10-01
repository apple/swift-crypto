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

public enum _CryptoRSAError: Error {
    case invalidPEMDocument
}

/// Errors that can be thrown when working with ``MLDSA``.
public enum CryptoMLDSAError: Error {
    /// The key generation with BoringSSL failed.
    case keyGenerationFailure
    /// The signature generation with BoringSSL failed.
    case signatureGenerationFailure
}
