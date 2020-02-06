//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Foundation
import XCTest

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL
@testable import Crypto
#endif

// This module implements "just enough" ASN.1. Specifically, we implement exactly enough ASN.1 DER parsing to handle
// taking the Wycheproof input of EC public keys and to turn them into the x963 representation of the key. This is not
// intended as production quality code, it's really intended to be just enough to get us through these tests.
//
// Let's talk about the DER encoding of ASN.1. DER is fundamentally a TLV (type length value) encoding. Each element is
// made of up some bytes that identify its type, some bytes that identify the length, and then the contents. In the full
// scheme of ASN.1 we care about a lot of things about its structure, but for our case we only care about a few kinds of
// tag. To work out the tag we need, we can look at the X.509 representation of an EC key, from RFC 5480:
//
// SubjectPublicKeyInfo  ::=  SEQUENCE  {
//   algorithm         AlgorithmIdentifier,
//   subjectPublicKey  BIT STRING
// }
//
// AlgorithmIdentifier  ::=  SEQUENCE  {
//   algorithm   OBJECT IDENTIFIER,
//   parameters  ANY DEFINED BY algorithm OPTIONAL
// }
//
// ECParameters ::= CHOICE {
//   namedCurve         OBJECT IDENTIFIER
//   -- implicitCurve   NULL
//   -- specifiedCurve  SpecifiedECDomain
// }
//
// For us, we expect the ECParameters structure to be using the namedCurve representation only.
//
// SEQUENCE, BIT STRING, and OBJECT IDENTIFIER are all primitive representations for ASN.1. Their relevant characteristics are:
//
// ┌───────────────────┬────────────┬──────────────────────────────────────────────┬────────────────┬───────────┐
// │ Name              │ Tag Number │ Primitive                                    │ Encoding Class │ Tag Bytes │
// ├───────────────────┼────────────┼──────────────────────────────────────────────┼────────────────┼───────────┤
// │ SEQUENCE          │       0x10 │                                            N │ Universal      │      0x30 │
// │ BIT STRING        │       0x03 │ Y (we don't support constructed bit strings) │ Universal      │      0x03 │
// │ OBJECT IDENTIFIER │       0x06 │                                            Y │ Universal      │      0x06 │
// └───────────────────┴────────────┴──────────────────────────────────────────────┴────────────────┴───────────┘
//
// In our case, we don't expect to see any parameters, and we're going to ignore them.
//
// The subjectPublicKey is required to be in x9.62 format, either compressed or uncompressed, so we can pass it directly to the
// initializers for CryptoKit once we've done the extraction.
//
// This is the complete set of things we need to be able to parse. It's not that big. Let's see how the code looks.

// MARK: - SPKI

struct ASN1SubjectPublicKeyInfo {
    var algorithm: ASN1AlgorithmIdentifier

    var subjectPublicKey: ASN1BitString

    init(fromASN1 bytes: inout ArraySlice<UInt8>) throws {
        guard bytes.first == 0x30 else {
            throw ECDHTestErrors.ParseSPKIFailure
        }
        bytes = bytes.dropFirst()

        var content = try bytes.readElementContent()

        self.algorithm = try ASN1AlgorithmIdentifier(fromASN1: &content)
        self.subjectPublicKey = try ASN1BitString(fromASN1: &content)
    }
}

// MARK: - AlgorithmIdentifier

struct ASN1AlgorithmIdentifier {
    var algorithm: ASN1ObjectIdentifier

    var namedCurve: ASN1ObjectIdentifier

    init(fromASN1 bytes: inout ArraySlice<UInt8>) throws {
        guard bytes.first == 0x30 else {
            throw ECDHTestErrors.ParseSPKIFailure
        }
        bytes = bytes.dropFirst()

        var content = try bytes.readElementContent()

        self.algorithm = try ASN1ObjectIdentifier(fromASN1: &content)
        self.namedCurve = try ASN1ObjectIdentifier(fromASN1: &content)
    }
}

// MARK: - Bitstring

// A bitstring is a representation of...well...some bits.
struct ASN1BitString {
    private var bytes: [UInt8]

    private static let tagByte = UInt8(0x03)

    init(fromASN1 bytes: inout ArraySlice<UInt8>) throws {
        guard bytes.first == ASN1BitString.tagByte else {
            throw ECDHTestErrors.ParseSPKIFailure
        }
        bytes = bytes.dropFirst()

        var content = try bytes.readElementContent()

        // The initial octet explains how many of the bits in the _final_ octet are not part of the bitstring.
        // The only value we support here is 0.
        guard content.first == 0 else {
            throw ECDHTestErrors.ParseSPKIFailure
        }

        content = content.dropFirst()
        self.bytes = Array(content)
    }
}

extension ASN1BitString: ContiguousBytes {
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
    }
}

// MARK: - ObjectIdentifier

// An Object Identifier is a representation of some kind of object: really any kind of object.
//
// It represents a node in an OID hierarchy, and is usually represented as an ordered sequence of numbers.
//
// We mostly don't care about the semantics of the thing, we just care about being able to store and compare them.
struct ASN1ObjectIdentifier {
    private var oidComponents: [UInt]

    private static let tagByte = UInt8(0x06)

    init(fromASN1 bytes: inout ArraySlice<UInt8>) throws {
        guard bytes.first == ASN1ObjectIdentifier.tagByte else {
            throw ECDHTestErrors.ParseSPKIFailure
        }
        bytes = bytes.dropFirst()

        var content = try bytes.readElementContent()

        // Now we have to parse the content. From the spec:
        //
        // > Each subidentifier is represented as a series of (one or more) octets. Bit 8 of each octet indicates whether it
        // > is the last in the series: bit 8 of the last octet is zero, bit 8 of each preceding octet is one. Bits 7 to 1 of
        // > the octets in the series collectively encode the subidentifier. Conceptually, these groups of bits are concatenated
        // > to form an unsigned binary number whose most significant bit is bit 7 of the first octet and whose least significant
        // > bit is bit 1 of the last octet. The subidentifier shall be encoded in the fewest possible octets[...].
        // >
        // > The number of subidentifiers (N) shall be one less than the number of object identifier components in the object identifier
        // > value being encoded.
        // >
        // > The numerical value of the first subidentifier is derived from the values of the first _two_ object identifier components
        // > in the object identifier value being encoded, using the formula:
        // >
        // >  (X*40) + Y
        // >
        // > where X is the value of the first object identifier component and Y is the value of the second object identifier component.
        //
        // Yeah, this is a bit bananas, but basically there are only 3 first OID components (0, 1, 2) and there are no more than 39 children
        // of nodes 0 or 1. In my view this is too clever by half, but the ITU.T didn't ask for my opinion when they were coming up with this
        // scheme, likely because I was in middle school at the time.
        var subcomponents = [UInt]()
        while content.count > 0 {
            subcomponents.append(try content.readOIDSubidentifier())
        }

        guard subcomponents.count >= 2 else {
            throw ECDHTestErrors.ParseSPKIFailure
        }

        // Now we need to expand the subcomponents out. This means we need to undo the step above. The first component will be in the range 0..<40
        // when the first oidComponent is 0, 40..<80 when the first oidComponent is 1, and 80+ when the first oidComponent is 2.
        var oidComponents = [UInt]()
        oidComponents.reserveCapacity(subcomponents.count + 1)

        switch subcomponents.first! {
        case ..<40:
            oidComponents.append(0)
            oidComponents.append(subcomponents.first!)
        case 40 ..< 80:
            oidComponents.append(1)
            oidComponents.append(subcomponents.first! - 40)
        default:
            oidComponents.append(2)
            oidComponents.append(subcomponents.first! - 80)
        }

        oidComponents.append(contentsOf: subcomponents.dropFirst())

        self.oidComponents = oidComponents
    }
}

extension ASN1ObjectIdentifier: Hashable {}

extension ASN1ObjectIdentifier: ExpressibleByArrayLiteral {
    init(arrayLiteral elements: UInt...) {
        self.oidComponents = elements
    }
}

extension ASN1ObjectIdentifier {
    enum NamedCurves {
        static let secp256r1: ASN1ObjectIdentifier = [1, 2, 840, 10045, 3, 1, 7]

        static let secp384r1: ASN1ObjectIdentifier = [1, 3, 132, 0, 34]

        static let secp521r1: ASN1ObjectIdentifier = [1, 3, 132, 0, 35]
    }

    enum AlgorithmIdentifier {
        static let idEcPublicKey: ASN1ObjectIdentifier = [1, 2, 840, 10045, 2, 1]
    }
}

// MARK: - Helpers

extension ArraySlice where Element == UInt8 {
    /// Returns an ArraySlice with the length of the ASN.1 section, and slices this slice to cover the remaining bytes.
    /// Requires the length to be at `startIndex`.
    mutating func readElementContent() throws -> ArraySlice<UInt8> {
        // We need to examine the start of this array as length bytes. This is a bit complex. For now, let's
        // only handle the definite form and error on the indefinite one.
        guard let firstByte = self.first else {
            throw ECDHTestErrors.ParseSPKIFailure
        }

        self = self.dropFirst()

        let length: UInt

        switch firstByte {
        case 0x80:
            // Indefinite form. Unsupported
            throw ECDHTestErrors.ParseSPKIFailure
        case let val where val & 0x80 == 0x80:
            // Top bit is set, this is the long form. The remaining 7 bits of this octet
            // determine how long the length field is.
            let fieldLength = Int(val & 0x7F)
            guard self.count >= fieldLength else {
                throw ECDHTestErrors.ParseSPKIFailure
            }

            // We need to read the length bytes.
            let lengthBytes = self.prefix(fieldLength)
            self = self.dropFirst(fieldLength)
            length = try UInt(bigEndianBytes: lengthBytes)
        case let val:
            // Short form, the length is only one 7-bit integer.
            length = UInt(val)
        }

        guard self.count >= length else {
            throw ECDHTestErrors.ParseSPKIFailure
        }

        let content = self.prefix(Int(length))
        self = self.dropFirst(Int(length))
        return content
    }

    mutating func readOIDSubidentifier() throws -> UInt {
        // In principle OID subidentifiers can be too large to fit into a UInt. We are choosing to not care about that
        // because for us it shouldn't matter.
        guard let subidentifierEndIndex = self.firstIndex(where: { $0 & 0x80 == 0x00 }) else {
            throw ECDHTestErrors.ParseSPKIFailure
        }

        let oidSlice = self[self.startIndex ... subidentifierEndIndex]
        self = self[self.index(after: subidentifierEndIndex)...]

        // We need to compact the bits. These are 7-bit integers, which is really awkward.
        return UInt(sevenBitBigEndianBytes: oidSlice)
    }
}

extension UInt {
    init<Bytes: Collection>(bigEndianBytes bytes: Bytes) throws where Bytes.Element == UInt8 {
        guard bytes.count <= MemoryLayout<UInt>.size else {
            throw ECDHTestErrors.ParseSPKIFailure
        }

        self = 0
        let shiftSizes = stride(from: 0, to: bytes.count * 8, by: 8).reversed()

        var index = bytes.startIndex
        for shift in shiftSizes {
            self |= UInt(bytes[index]) << shift
            bytes.formIndex(after: &index)
        }
    }

    init<Bytes: Collection>(sevenBitBigEndianBytes bytes: Bytes) where Bytes.Element == UInt8 {
        // We need to know how many bytes we _need_ to store this "int".
        guard ((bytes.count * 7) + 7) / 8 <= MemoryLayout<UInt>.size else {
            fatalError("Too big to parse")
        }

        self = 0
        let shiftSizes = stride(from: 0, to: bytes.count * 7, by: 7).reversed()

        var index = bytes.startIndex
        for shift in shiftSizes {
            self |= UInt(bytes[index] & 0x7F) << shift
            bytes.formIndex(after: &index)
        }
    }
}

#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM
