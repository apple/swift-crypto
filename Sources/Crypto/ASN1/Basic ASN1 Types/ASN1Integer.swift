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
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
import Foundation

// Going forward this should probably be a real separate type, but it's somewhat convenient for now to just extend `Int`.
extension Int: ASN1Parseable, ASN1Serializable {
    internal init(asn1Encoded node: ASN1.ASN1Node) throws {
        guard node.identifier == .integer else {
            throw CryptoKitASN1Error.unexpectedFieldType
        }

        guard case .primitive(let dataBytes) = node.content else {
            preconditionFailure("ASN.1 parser generated primitive node with constructed content")
        }

        // Zero bytes of integer is not an acceptable encoding.
        guard dataBytes.count > 0 else {
            throw CryptoKitASN1Error.invalidASN1IntegerEncoding
        }

        // 8.3.2 If the contents octets of an integer value encoding consist of more than one octet, then the bits of the first octet and bit 8 of the second octet:
        //
        // a) shall not all be ones; and
        // b) shall not all be zero.
        //
        // NOTE – These rules ensure that an integer value is always encoded in the smallest possible number of octets.
        if let first = dataBytes.first, let second = dataBytes.dropFirst().first {
            if ((first & 0xFF == 0xFF) && (second & 0x80 == 0x80)) ||
                ((first & 0xFF == 0x00) && (second & 0x80 == 0x00)) {
                throw CryptoKitASN1Error.invalidASN1IntegerEncoding
            }
        }
        self = try Int(bigEndianBytes: dataBytes)
    }

    internal func serialize(into coder: inout ASN1.Serializer) throws {
        coder.appendPrimitiveNode(identifier: .integer) { bytes in
            // We need to use the minimal number of bytes here.
            let neededBytes = UInt(self).neededBytes

            // If needed bytes is 0, we're encoding a zero. That actually _does_ require one byte.
            if neededBytes == 0 {
                bytes.append(0)
                return
            }

            for byteNumber in (0..<neededBytes).reversed() {
                let shift = byteNumber * 8
                bytes.append(UInt8((self >> shift) & 0xFF))
            }
        }
    }
}

extension Int {
    fileprivate init<Bytes: Collection>(bigEndianBytes bytes: Bytes) throws where Bytes.Element == UInt8 {
        let bitPattern = try UInt(bigEndianBytes: bytes)
        self = Int(bitPattern: bitPattern)
    }
}

#endif // Linux or !SwiftPM
