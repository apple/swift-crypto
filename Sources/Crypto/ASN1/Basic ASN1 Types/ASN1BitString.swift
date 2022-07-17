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

extension ASN1 {
    /// A bitstring is a representation of...well...some bits.
    struct ASN1BitString: ASN1ImplicitlyTaggable {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .primitiveBitString
        }

        var bytes: ArraySlice<UInt8>

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            guard node.identifier == identifier else {
                throw CryptoKitASN1Error.unexpectedFieldType
            }

            guard case .primitive(let content) = node.content else {
                preconditionFailure("ASN.1 parser generated primitive node with constructed content")
            }

            // The initial octet explains how many of the bits in the _final_ octet are not part of the bitstring.
            // The only value we support here is 0.
            guard content.first == 0 else {
                throw CryptoKitASN1Error.invalidASN1Object
            }

            self.bytes = content.dropFirst()
        }

        init(bytes: ArraySlice<UInt8>) {
            self.bytes = bytes
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            coder.appendPrimitiveNode(identifier: identifier) { bytes in
                bytes.append(0)
                bytes.append(contentsOf: self.bytes)
            }
        }
    }
}

extension ASN1.ASN1BitString: Hashable { }

extension ASN1.ASN1BitString: ContiguousBytes {
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
    }
}

#endif // Linux or !SwiftPM
