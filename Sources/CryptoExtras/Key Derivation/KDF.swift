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
import Foundation
#endif

/// A container for Key Detivation Function algorithms.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum KDF: Sendable {
    /// A container for older, cryptographically insecure algorithms.
    ///
    /// - Important: These algorithms aren’t considered cryptographically secure,
    /// but the framework provides them for backward compatibility with older
    /// services that require them. For new services, avoid these algorithms.
    public enum Insecure: Sendable {}
}
