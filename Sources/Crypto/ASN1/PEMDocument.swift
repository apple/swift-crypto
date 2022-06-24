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
    /// A PEM document is some data, and a discriminator type that is used to advertise the content.
    struct PEMDocument {
        private static let lineLength = 64

        var type: String

        var derBytes: Data

        init(pemString: String) throws {
            // A PEM document looks like this:
            //
            // -----BEGIN <SOME DISCRIMINATOR>-----
            // <base64 encoded bytes, 64 characters per line>
            // -----END <SOME DISCRIMINATOR>-----
            //
            // This function attempts to parse this string as a PEM document, and returns the discriminator type
            // and the base64 decoded bytes.
            var lines = pemString.split { $0.isNewline }[...]
            guard let first = lines.first, let last = lines.last else {
                throw CryptoKitASN1Error.invalidPEMDocument
            }

            guard let discriminator = first.pemStartDiscriminator, discriminator == last.pemEndDiscriminator else {
                throw CryptoKitASN1Error.invalidPEMDocument
            }

            // All but the last line must be 64 bytes. The force unwrap is safe because we require the lines to be
            // greater than zero.
            lines = lines.dropFirst().dropLast()
            guard lines.count > 0,
                lines.dropLast().allSatisfy({ $0.utf8.count == PEMDocument.lineLength }),
                lines.last!.utf8.count <= PEMDocument.lineLength else {
                throw CryptoKitASN1Error.invalidPEMDocument
            }

            guard let derBytes = Data(base64Encoded: lines.joined()) else {
                throw CryptoKitASN1Error.invalidPEMDocument
            }

            self.type = discriminator
            self.derBytes = derBytes
        }

        init(type: String, derBytes: Data) {
            self.type = type
            self.derBytes = derBytes
        }

        var pemString: String {
            var encoded = self.derBytes.base64EncodedString()[...]
            let pemLineCount = (encoded.utf8.count + PEMDocument.lineLength) / PEMDocument.lineLength
            var pemLines = [Substring]()
            pemLines.reserveCapacity(pemLineCount + 2)

            pemLines.append("-----BEGIN \(self.type)-----")

            while encoded.count > 0 {
                let prefixIndex = encoded.index(encoded.startIndex, offsetBy: PEMDocument.lineLength, limitedBy: encoded.endIndex) ?? encoded.endIndex
                pemLines.append(encoded[..<prefixIndex])
                encoded = encoded[prefixIndex...]
            }

            pemLines.append("-----END \(self.type)-----")

            return pemLines.joined(separator: "\n")
        }
    }
}

extension Substring {
    fileprivate var pemStartDiscriminator: String? {
        return self.pemDiscriminator(expectedPrefix: "-----BEGIN ", expectedSuffix: "-----")
    }

    fileprivate var pemEndDiscriminator: String? {
        return self.pemDiscriminator(expectedPrefix: "-----END ", expectedSuffix: "-----")
    }

    private func pemDiscriminator(expectedPrefix: String, expectedSuffix: String) -> String? {
        var utf8Bytes = self.utf8[...]

        // We want to split this sequence into three parts: the prefix, the middle, and the end
        let prefixSize = expectedPrefix.utf8.count
        let suffixSize = expectedSuffix.utf8.count

        let prefix = utf8Bytes.prefix(prefixSize)
        utf8Bytes = utf8Bytes.dropFirst(prefixSize)
        let suffix = utf8Bytes.suffix(suffixSize)
        utf8Bytes = utf8Bytes.dropLast(suffixSize)

        guard prefix.elementsEqual(expectedPrefix.utf8), suffix.elementsEqual(expectedSuffix.utf8) else {
            return nil
        }

        return String(utf8Bytes)
    }
}

#endif // Linux or !SwiftPM
