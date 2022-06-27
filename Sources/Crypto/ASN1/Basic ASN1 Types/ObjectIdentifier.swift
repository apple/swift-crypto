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
    /// An Object Identifier is a representation of some kind of object: really any kind of object.
    ///
    /// It represents a node in an OID hierarchy, and is usually represented as an ordered sequence of numbers.
    ///
    /// We mostly don't care about the semantics of the thing, we just care about being able to store and compare them.
    struct ASN1ObjectIdentifier: ASN1ImplicitlyTaggable {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .objectIdentifier
        }

        private var oidComponents: [UInt]

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            guard node.identifier == identifier else {
                throw CryptoKitASN1Error.unexpectedFieldType
            }

            guard case .primitive(var content) = node.content else {
                preconditionFailure("ASN.1 parser generated primitive node with constructed content")
            }

            // We have to parse the content. From the spec:
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
                throw CryptoKitASN1Error.invalidObjectIdentifier
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

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            coder.appendPrimitiveNode(identifier: identifier) { bytes in
                var components = self.oidComponents[...]
                guard let firstComponent = components.popFirst(), let secondComponent = components.popFirst() else {
                    preconditionFailure("Invalid number of OID components: must be at least two!")
                }

                let serializedFirstComponent = (firstComponent * 40) + secondComponent
                ASN1ObjectIdentifier.writeOIDSubidentifier(serializedFirstComponent, into: &bytes)

                while let component = components.popFirst() {
                    ASN1ObjectIdentifier.writeOIDSubidentifier(component, into: &bytes)
                }
            }
        }

        private static func writeOIDSubidentifier(_ identifier: UInt, into array: inout [UInt8]) {
            // An OID subidentifier is written as an integer over 7-bit bytes, where the last byte has the top bit unset.
            // The first thing we need is to know how many bits we need to write
            let bitsToWrite = UInt.bitWidth - identifier.leadingZeroBitCount
            let bytesToWrite = (bitsToWrite + 6) / 7

            guard bytesToWrite > 0 else {
                // Just a zero.
                array.append(0)
                return
            }

            for byteNumber in (1..<bytesToWrite).reversed() {
                let shift = byteNumber * 7
                let byte = UInt8((identifier >> shift) & 0x7f) | 0x80
                array.append(byte)
            }

            // Last byte to append here, we must unset the top bit.
            let byte = UInt8((identifier & 0x7F))
            array.append(byte)
        }
    }
}

extension ASN1.ASN1ObjectIdentifier: Hashable {}

extension ASN1.ASN1ObjectIdentifier: ExpressibleByArrayLiteral {
        init(arrayLiteral elements: UInt...) {
            self.oidComponents = elements
        }
    }

extension ASN1.ASN1ObjectIdentifier {
    enum NamedCurves {
        static let secp256r1: ASN1.ASN1ObjectIdentifier = [1, 2, 840, 10_045, 3, 1, 7]

        static let secp384r1: ASN1.ASN1ObjectIdentifier = [1, 3, 132, 0, 34]

        static let secp521r1: ASN1.ASN1ObjectIdentifier = [1, 3, 132, 0, 35]
    }
    
    enum HashFunctions {
        static let sha256: ASN1.ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 1]
        static let sha384: ASN1.ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 2]
        static let sha512: ASN1.ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 3]
    }

    enum AlgorithmIdentifier {
        static let idEcPublicKey: ASN1.ASN1ObjectIdentifier = [1, 2, 840, 10_045, 2, 1]
    }

    enum NameAttributes {
        static let name: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 41]
        static let surname: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 4]
        static let givenName: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 42]
        static let initials: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 43]
        static let generationQualifier: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 44]
        static let commonName: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 3]
        static let localityName: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 7]
        static let stateOrProvinceName: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 8]
        static let organizationName: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 10]
        static let organizationalUnitName: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 11]
        static let title: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 12]
        static let dnQualifier: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 46]
        static let countryName: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 6]
        static let serialNumber: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 5]
        static let pseudonym: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 65]
        static let domainComponent: ASN1.ASN1ObjectIdentifier = [0, 9, 2342, 19_200_300, 100, 1, 25]
        static let emailAddress: ASN1.ASN1ObjectIdentifier = [1, 2, 840, 113_549, 1, 9, 1]
    }

}

extension ArraySlice where Element == UInt8 {
    mutating fileprivate func readOIDSubidentifier() throws -> UInt {
        // In principle OID subidentifiers can be too large to fit into a UInt. We are choosing to not care about that
        // because for us it shouldn't matter.
        guard let subidentifierEndIndex = self.firstIndex(where: { $0 & 0x80 == 0x00 }) else {
            throw CryptoKitASN1Error.invalidASN1Object
        }

        let oidSlice = self[self.startIndex ... subidentifierEndIndex]
        self = self[self.index(after: subidentifierEndIndex)...]

        // We need to compact the bits. These are 7-bit integers, which is really awkward.
        return try UInt(sevenBitBigEndianBytes: oidSlice)
    }
}

extension UInt {
    fileprivate init<Bytes: Collection>(sevenBitBigEndianBytes bytes: Bytes) throws where Bytes.Element == UInt8 {
        // We need to know how many bytes we _need_ to store this "int".
        guard ((bytes.count * 7) + 7) / 8 <= MemoryLayout<UInt>.size else {
            throw CryptoKitASN1Error.invalidASN1Object
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

#endif // Linux or !SwiftPM
