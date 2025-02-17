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

#if canImport(Darwin) && !CRYPTO_IN_SWIFTPM
typealias SupportedCurveDetailsImpl = CorecryptoSupportedNISTCurve
typealias GroupImpl = CoreCryptoGroup
typealias HashToCurveImpl = CoreCryptoHashToCurve
#else
typealias SupportedCurveDetailsImpl = OpenSSLSupportedNISTCurve
typealias GroupImpl = OpenSSLGroup
@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, *)
typealias HashToCurveImpl = OpenSSLHashToCurve
#endif

/// A prime-order group
protocol Group {
    /// Group element
    associatedtype Element: GroupElement

    /// Group scalar (mod p) where p is the order of the group
    typealias Scalar = Element.Scalar

    /// Cofactor of the group
    static var cofactor: Int { get }
}

protocol HashToGroup {
    associatedtype H: HashFunction
    associatedtype G: Group where G.Element: OPRFGroupElement

    static func hashToScalar(_ data: Data, domainSeparationString: Data) throws -> G.Scalar
    static func hashToGroup(_ data: Data, domainSeparationString: Data) -> G.Element
}

protocol GroupScalar {
    init(bytes: Data, reductionIsModOrder: Bool) throws

    var rawRepresentation: Data { get }

    // Generates a Random Scalar Element
    static var random: Self { get }

    static func + (left: Self, right: Self) -> Self

    static func - (left: Self, right: Self) -> Self

    static func ^ (left: Self, right: Int) -> Self

    static func * (left: Self, right: Self) -> Self

    static prefix func - (left: Self) -> Self

    // Constant-time Comparison
    static func == (left: Self, right: Self) -> Bool
}

protocol GroupElement {
    associatedtype Scalar: GroupScalar

    static var generator: Self { get }

    // Generates a Random Group Element
    static var random: Self { get }

    static func + (left: Self, right: Self) -> Self

    static func - (left: Self, right: Self) -> Self

    static prefix func - (left: Self) -> Self

    // Group Point Multiplication
    static func * (left: Scalar, right: Self) -> Self
    // Constant-time Comparison
    static func == (left: Self, right: Self) -> Bool
}
