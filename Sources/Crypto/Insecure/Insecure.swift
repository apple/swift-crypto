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

#if canImport(CryptoKit)
@_exported import CryptoKit
#else
/// A container for older, cryptographically insecure algorithms.
///
/// - Important: These algorithms aren’t considered cryptographically secure,
/// but the framework provides them for backward compatibility with older
/// services that require them. For new services, avoid these algorithms.
@nonexhaustive
public enum Insecure: Sendable {}
#endif // canImport(CryptoKit)
