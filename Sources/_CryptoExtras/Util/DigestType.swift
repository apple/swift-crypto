//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if !canImport(Security)
@_implementationOnly import CCryptoBoringSSL
import Crypto

struct DigestType {
    var dispatchTable: OpaquePointer

    var nid: CInt

    var digestLength: Int

    /// The dispatchtable pointer must have static storage and not be lifetime managed,
    /// as it is assumed to last for the duration of the program.
    private init(_ dispatchTable: OpaquePointer, _ nid: CInt, digestLength: Int) {
        self.dispatchTable = dispatchTable
        self.nid = nid
        self.digestLength = digestLength
    }

    static let sha1 = DigestType(CCryptoBoringSSL_EVP_sha1(), NID_sha1, digestLength: 20)

    static let sha256 = DigestType(CCryptoBoringSSL_EVP_sha256(), NID_sha256, digestLength: 32)

    static let sha384 = DigestType(CCryptoBoringSSL_EVP_sha384(), NID_sha384, digestLength: 48)

    static let sha512 = DigestType(CCryptoBoringSSL_EVP_sha512(), NID_sha512, digestLength: 64)

    init<DGT: Digest>(forDigestType digestType: DGT.Type = DGT.self) throws {
        switch digestType {
        case is Insecure.SHA1.Digest.Type:
            self = .sha1
        case is SHA256.Digest.Type:
            self = .sha256
        case is SHA384.Digest.Type:
            self = .sha384
        case is SHA512.Digest.Type:
            self = .sha512
        default:
            throw CryptoKitError.incorrectParameterSize
        }
    }
}
#endif
