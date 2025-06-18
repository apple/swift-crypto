//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021-2024 Apple Inc. and the SwiftCrypto project authors
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

#if canImport(CommonCrypto)
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
fileprivate typealias BackingPBKDF2 = CommonCryptoPBKDF2
#else
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
fileprivate typealias BackingPBKDF2 = BoringSSLPBKDF2
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension KDF.Insecure {
    /// An implementation of PBKDF2 key derivation function.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct PBKDF2: Sendable {
        /// Derives a symmetric key using the PBKDF2 algorithm.
        ///
        /// - Parameters:
        ///    - password: The passphrase, which should be used as a basis for the key. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
        ///    - salt: The salt to use for key derivation.
        ///    - hashFunction: The hash function to use for key derivation.
        ///    - outputByteCount: The length in bytes of resulting symmetric key.
        ///    - rounds: The number of rounds which should be used to perform key derivation. The minimum allowed number of rounds is 210,000.
        /// - Throws: An error if the number of rounds is less than 210,000
        /// - Note: The correct choice of rounds depends on a number of factors such as the hash function used, the speed of the target machine, and the intended use of the derived key. A good rule of thumb is to use rounds in the hundered of thousands or millions. For more information see OWASP's [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
        /// - Returns: The derived symmetric key.
        public static func deriveKey<Passphrase: DataProtocol, Salt: DataProtocol>(from password: Passphrase, salt: Salt, using hashFunction: HashFunction, outputByteCount: Int, rounds: Int) throws -> SymmetricKey {
            guard rounds >= 210_000 else {
                throw CryptoKitError.incorrectParameterSize
            }
            return try PBKDF2.deriveKey(from: password, salt: salt, using: hashFunction, outputByteCount: outputByteCount, unsafeUncheckedRounds: rounds)
        }
        
        /// Derives a symmetric key using the PBKDF2 algorithm.
        ///
        /// - Parameters:
        ///    - password: The passphrase, which should be used as a basis for the key. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
        ///    - salt: The salt to use for key derivation.
        ///    - hashFunction: The hash function to use for key derivation.
        ///    - outputByteCount: The length in bytes of resulting symmetric key.
        ///    - unsafeUncheckedRounds: The number of rounds which should be used to perform key derivation.
        /// - Warning: This method allows the use of parameters which may result in insecure keys. It is important to ensure that the used parameters do not compromise the security of the application.
        /// - Returns: The derived symmetric key.
        public static func deriveKey<Passphrase: DataProtocol, Salt: DataProtocol>(from password: Passphrase, salt: Salt, using hashFunction: HashFunction, outputByteCount: Int, unsafeUncheckedRounds: Int) throws -> SymmetricKey {
            return try BackingPBKDF2.deriveKey(from: password, salt: salt, using: hashFunction, outputByteCount: outputByteCount, rounds: unsafeUncheckedRounds)
        }
        
        public struct HashFunction: Equatable, Hashable, Sendable {
            let rawValue: String
            
            public static let insecureMD5 = HashFunction(rawValue: "insecure_md5")
            public static let insecureSHA1 = HashFunction(rawValue: "insecure_sha1")
            public static let insecureSHA224 = HashFunction(rawValue: "insecure_sha224")
            public static let sha256 = HashFunction(rawValue: "sha256")
            public static let sha384 = HashFunction(rawValue: "sha384")
            public static let sha512 = HashFunction(rawValue: "sha512")
            
            init(rawValue: String) {
                self.rawValue = rawValue
            }
        }
    }
}
