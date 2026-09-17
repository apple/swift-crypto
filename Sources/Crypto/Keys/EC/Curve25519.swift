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
/// An elliptic curve that enables X25519 key agreement and Ed25519 signatures.
@nonexhaustive
public enum Curve25519: Sendable {}
#endif // canImport(CryptoKit)
