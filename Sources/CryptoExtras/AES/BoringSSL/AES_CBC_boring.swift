//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CCryptoBoringSSL
import Crypto

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
@usableFromInline
enum OpenSSLAESCBCImpl {
    private static let blockSize = 16

    @usableFromInline
    enum Direction {
        case encrypt
        case decrypt

        @usableFromInline
        var _boringSSLParameter: Int32 {
            switch self {
            case .encrypt: AES_ENCRYPT
            case .decrypt: AES_DECRYPT
            }
        }
    }

    /// Encrypts plaintext using AES-CBC.
    ///
    /// PKCS#7 padding is added unless `noPadding` is set, in which case the plaintext must
    /// already be a whole number of blocks.
    static func encrypt<Plaintext: DataProtocol>(
        _ plaintext: Plaintext,
        using key: SymmetricKey,
        iv: AES._CBC.IV,
        noPadding: Bool
    ) throws -> Data {
        guard [128, 192, 256].contains(key.bitCount) else {
            throw CryptoKitError.incorrectKeySize
        }
        // With padding disabled the input must be a whole number of blocks.
        if noPadding && (plaintext.count % Self.blockSize != 0) {
            throw CryptoKitError.incorrectParameterSize
        }

        // AES_cbc_encrypt performs no padding, so PKCS#7 is applied here.
        var padded = Data(plaintext)
        if !noPadding {
            // PKCS#7 always appends 1...blockSize bytes (a full block when already aligned).
            let padLength = Self.blockSize - (plaintext.count % Self.blockSize)
            let padding = repeatElement(UInt8(padLength), count: padLength)
            padded.append(contentsOf: padding)
        }

        return padded.withUnsafeBytes { plaintextPtr in
            Self._cipher(.encrypt, plaintextPtr, using: key, iv: iv)
        }
    }

    /// Decrypts ciphertext using AES-CBC.
    ///
    /// BoringSSL runs with padding disabled and, unless `noPadding` is set, PKCS#7 padding is
    /// removed here in constant time. BoringSSL's own PKCS#7 removal is not constant-time (it is a
    /// documented padding oracle absent authentication), so it must not be delegated.
    static func decrypt<Ciphertext: DataProtocol>(
        _ ciphertext: Ciphertext,
        using key: SymmetricKey,
        iv: AES._CBC.IV,
        noPadding: Bool
    ) throws -> Data {
        guard [128, 192, 256].contains(key.bitCount) else {
            throw CryptoKitError.incorrectKeySize
        }
        // CBC ciphertext is always a whole number of non-empty blocks.
        guard ciphertext.count > 0, ciphertext.count % Self.blockSize == 0 else {
            throw CryptoKitError.incorrectParameterSize
        }

        let contiguousCiphertext = Data(ciphertext)
        let plaintext = contiguousCiphertext.withUnsafeBytes { ciphertextPtr in
            Self._cipher(.decrypt, ciphertextPtr, using: key, iv: iv)
        }

        return noPadding ? plaintext : try plaintext.removingPKCS7PaddingConstantTime(blockSize: Self.blockSize)
    }

    /// Runs raw AES-CBC in the given direction over a single contiguous buffer.
    ///
    /// `AES_cbc_encrypt` performs no padding, so `input` must be a whole number of blocks and the
    /// output has the same length. PKCS#7 is applied and removed by the callers.
    @usableFromInline
    static func _cipher(
        _ direction: Direction,
        _ input: UnsafeRawBufferPointer,
        using key: SymmetricKey,
        iv: AES._CBC.IV
    ) -> Data {
        precondition(input.count % Self.blockSize == 0)

        var output = Data(count: input.count)
        var iv = iv
        key.withUnsafeBytes { keyPtr in
            // AES_cbc_encrypt advances the IV in place, so operate on our own copy.
            iv.withUnsafeMutableBytes { ivPtr in
                var key = AES_KEY()
                switch direction {
                case .encrypt:
                    precondition(
                        CCryptoBoringSSL_AES_set_encrypt_key(keyPtr.baseAddress, UInt32(keyPtr.count * 8), &key) == 0
                    )
                case .decrypt:
                    precondition(
                        CCryptoBoringSSL_AES_set_decrypt_key(keyPtr.baseAddress, UInt32(keyPtr.count * 8), &key) == 0
                    )
                }
                output.withUnsafeMutableBytes { outputPtr in
                    CCryptoBoringSSL_AES_cbc_encrypt(
                        input.baseAddress,
                        outputPtr.baseAddress,
                        input.count,
                        &key,
                        ivPtr.baseAddress,
                        direction._boringSSLParameter
                    )
                }
            }
        }

        return output
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Data {
    /// Removes PKCS#7 padding in constant time with respect to the padding bytes.
    fileprivate func removingPKCS7PaddingConstantTime(blockSize: Int = 16) throws -> Data {
        // The total length is not secret, so branching on it is safe.
        guard self.count >= blockSize, self.count % blockSize == 0 else {
            throw CryptoKitError.incorrectParameterSize
        }

        let padLength = self.last!
        let lastBlock = self.suffix(blockSize)

        // Validate padding in constant time.
        var bad: UInt32 = 0
        // A valid PKCS#7 pad length is 1...blockSize.
        bad |= constantTimeLessThanOrEqual(padLength, 0)
        bad |= constantTimeLessThanOrEqual(UInt8(blockSize + 1), padLength)
        // We MUST operate on every byte in the block, and each byte in the padding region MUST equal `padLength`.
        for index in lastBlock.indices {
            let byte = UInt32(lastBlock[index])
            let distanceFromEnd = self.endIndex - index
            let inPadding = constantTimeLessThanOrEqual(UInt8(distanceFromEnd), padLength)
            bad |= inPadding & (byte ^ UInt32(padLength))
        }

        // Throw if padding was invalid.
        guard bad == 0 else {
            throw CryptoKitError.incorrectParameterSize
        }

        // Drop the padding.
        return self.dropLast(Int(padLength))
    }
}

/// Returns `0xFFFFFFFF` if `lhs <= rhs`, otherwise `0`, without a data-dependent branch.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
private func constantTimeLessThanOrEqual(_ lhs: UInt8, _ rhs: UInt8) -> UInt32 {
    // `lhs - rhs - 1` is negative iff `lhs <= rhs`; propagate its sign bit across the word.
    let difference = Int32(lhs) - Int32(rhs) - 1
    return UInt32(bitPattern: difference >> 31)
}
