//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
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

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
extension AES {
    /// A cipher-based message authentication code.
    ///
    /// CMAC uses AES to implement a MAC.  CMAC is useful in contexts where access to
    /// a hash function is not guaranteed, but a block cipher will be available.
    public struct CMAC: @unchecked Sendable {
        // Unchecked sendable because this is CoW.
        fileprivate var backing: Backing

        /// Creates a message authentication code generator.
        ///
        /// Defaults the output size to 128 bits.
        ///
        /// - Parameters:
        ///   - key: The symmetric key used to secure the computation.
        public init(key: SymmetricKey) throws {
            try self.init(key: key, outputSize: 16)
        }

        /// Creates a message authentication code generator.
        ///
        /// - Parameters:
        ///   - key: The symmetric key used to secure the computation.
        ///   - outputSize: The number of bytes of MAC to generate. Must be in the range 0 to 16 inclusive.
        public init(key: SymmetricKey, outputSize: Int) throws {
            guard [128, 192, 256].contains(key.bitCount) else {
                throw CryptoError.incorrectKeySize
            }
            guard (0...16).contains(outputSize) else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.backing = Backing(key: key, outputSize: outputSize)
        }

        /// Adds data to be authenticated by MAC function. This can be called one or more times to append additional data.
        ///
        /// - Parameters:
        ///   - bufferPointer: The data to be authenticated.
        public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
            self.cowIfNeeded()
            self.backing.update(bufferPointer)
        }

        // This enhancement can only be present on 6.1 or later because of the
        // absence of https://github.com/swiftlang/swift/pull/76186 in older
        // compilers.
        #if compiler(>=6.1)
        /// Finalizes the message authentication computation and returns the
        /// computed code.
        ///
        /// - Returns: The message authentication code.
        public consuming func finalize() -> AES.CMAC.MAC {
            // The combination of "consuming" and "cowifneeded" should
            // produce an environment where, if users may choose to
            // keep using the MAC, they can, but if they aren't we'll
            // avoid an unnecessary CoW.
            self.cowIfNeeded()
            return self.backing.finalize()
        }
        #else
        /// Finalizes the message authentication computation and returns the
        /// computed code.
        ///
        /// - Returns: The message authentication code.
        public func finalize() -> AES.CMAC.MAC {
            var `self` = self
            return self.backing.finalize()
        }
        #endif

        /// Updates the MAC with data.
        ///
        /// - Parameter data: The data to update the MAC
        public mutating func update<D: DataProtocol>(data: D) {
            for memoryRegion in data.regions {
                memoryRegion.withUnsafeBytes { bp in
                    self.update(bufferPointer: bp)
                }
            }
        }

        private mutating func cowIfNeeded() {
            if !isKnownUniquelyReferenced(&self.backing) {
                self.backing = Backing(copying: self.backing)
            }
        }
    }
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
extension AES.CMAC {
    /// A cipher-based message authentication code.
    public struct MAC: MessageAuthenticationCode {
        fileprivate let underlyingData: Data

        init(underlyingData: Data) {
            self.underlyingData = underlyingData
        }

        /// The number of bytes in the message authentication code.
        public var byteCount: Int {
            self.underlyingData.count
        }

        /// Invokes the given closure with a buffer pointer covering the raw bytes
        /// of the code.
        ///
        /// - Parameters:
        ///   - body: A closure that takes a raw buffer pointer to the bytes of the
        ///       code.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.underlyingData.withUnsafeBytes(body)
        }
    }
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
extension AES.CMAC {
    fileprivate final class Backing {
        private let key: SymmetricKey
        private let context: OpaquePointer
        private let outputSize: Int

        init(key: SymmetricKey, outputSize: Int) {
            self.key = key
            self.context = CCryptoBoringSSL_CMAC_CTX_new()
            self.outputSize = outputSize

            let rc = self.key.withUnsafeBytes { keyPtr in
                CCryptoBoringSSL_CMAC_Init(
                    self.context,
                    keyPtr.baseAddress,
                    keyPtr.count,
                    key.aesEVP,
                    nil
                )
            }
            precondition(rc == 1)
        }

        init(copying other: Backing) {
            self.key = other.key
            self.context = CCryptoBoringSSL_CMAC_CTX_new()
            self.outputSize = other.outputSize
            let rc = CCryptoBoringSSL_CMAC_CTX_copy(self.context, other.context)
            precondition(rc == 1)

            // Ensure we don't lose `other` at this time.
            withExtendedLifetime(other) {}
        }

        deinit {
            CCryptoBoringSSL_CMAC_CTX_free(self.context)
        }

        func update(_ bytes: UnsafeRawBufferPointer) {
            let rc = CCryptoBoringSSL_CMAC_Update(self.context, bytes.baseAddress, bytes.count)
            precondition(rc == 1)
        }

        func finalize() -> AES.CMAC.MAC {
            let bytes = withUnsafeTemporaryAllocation(byteCount: 16, alignment: 1) { bytes in
                precondition(bytes.count >= 16)
                var count = 16
                let rc = CCryptoBoringSSL_CMAC_Final(self.context, bytes.baseAddress, &count)
                precondition(count == 16)
                precondition(rc == 1)

                return Data(UnsafeRawBufferPointer(rebasing: bytes.prefix(self.outputSize)))
            }
            return AES.CMAC.MAC(underlyingData: bytes)
        }
    }
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
extension SymmetricKey {
    fileprivate var aesEVP: OpaquePointer {
        switch self.bitCount {
        case 128:
            CCryptoBoringSSL_EVP_aes_128_cbc()
        case 192:
            CCryptoBoringSSL_EVP_aes_192_cbc()
        case 256:
            CCryptoBoringSSL_EVP_aes_256_cbc()
        default:
            fatalError("Should be unreachable")
        }
    }
}
