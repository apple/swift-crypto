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
@_exported import CryptoKit
#else
/// A container for older, cryptographically insecure algorithms.
///
/// - Important: These algorithms aren’t considered cryptographically secure,
/// but the framework provides them for backward compatibility with older
/// services that require them. For new services, avoid these algorithms.
public enum Insecure {}
#endif // Linux or !SwiftPM
