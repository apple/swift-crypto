//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Crypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
#if canImport(Darwin) || swift(>=5.9.1)
import Foundation
#else
@preconcurrency import Foundation
#endif
#endif

/// A container for Key Detivation Function algorithms.
public enum KDF: Sendable {
    /// A container for older, cryptographically insecure algorithms.
    ///
    /// - Important: These algorithms aren’t considered cryptographically secure,
    /// but the framework provides them for backward compatibility with older
    /// services that require them. For new services, avoid these algorithms.
    public enum Insecure: Sendable {}
}
