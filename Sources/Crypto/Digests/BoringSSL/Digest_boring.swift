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
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL

protocol HashFunctionImplementationDetails: HashFunction where Digest: DigestPrivate {}

protocol BoringSSLBackedHashFunction: HashFunctionImplementationDetails {
    static var digestType: DigestContext.DigestType { get }
}

extension Insecure.MD5: BoringSSLBackedHashFunction {
    static var digestType: DigestContext.DigestType {
        return .md5
    }
}

extension Insecure.SHA1: BoringSSLBackedHashFunction {
    static var digestType: DigestContext.DigestType {
        return .sha1
    }
}

extension SHA256: BoringSSLBackedHashFunction {
    static var digestType: DigestContext.DigestType {
        return .sha256
    }
}

extension SHA384: BoringSSLBackedHashFunction {
    static var digestType: DigestContext.DigestType {
        return .sha384
    }
}

extension SHA512: BoringSSLBackedHashFunction {
    static var digestType: DigestContext.DigestType {
        return .sha512
    }
}

struct OpenSSLDigestImpl<H: BoringSSLBackedHashFunction> {
    private var context: DigestContext

    init() {
        self.context = DigestContext(digest: H.digestType)
    }

    internal mutating func update(data: UnsafeRawBufferPointer) {
        if !isKnownUniquelyReferenced(&self.context) {
            self.context = DigestContext(copying: self.context)
        }
        self.context.update(data: data)
    }

    internal func finalize() -> H.Digest {
        // To have a non-destructive finalize operation we must allocate.
        let copyContext = DigestContext(copying: self.context)
        let digestBytes = copyContext.finalize()
        return digestBytes.withUnsafeBytes {
            // We force unwrap here because if the digest size is wrong it's an internal error.
            H.Digest(bufferPointer: $0)!
        }
    }
}

class DigestContext {
    private var contextPointer: UnsafeMutablePointer<EVP_MD_CTX>

    init(digest: DigestType) {
        // We force unwrap because we cannot recover from allocation failure.
        self.contextPointer = CCryptoBoringSSL_EVP_MD_CTX_new()!
        guard CCryptoBoringSSL_EVP_DigestInit(self.contextPointer, digest.dispatchTable) != 0 else {
            // We can't do much but crash here.
            fatalError("Unable to initialize digest state: \(CCryptoBoringSSL_ERR_get_error())")
        }
    }

    init(copying original: DigestContext) {
        // We force unwrap because we cannot recover from allocation failure.
        self.contextPointer = CCryptoBoringSSL_EVP_MD_CTX_new()!
        guard CCryptoBoringSSL_EVP_MD_CTX_copy(self.contextPointer, original.contextPointer) != 0 else {
            // We can't do much but crash here.
            fatalError("Unable to copy digest state: \(CCryptoBoringSSL_ERR_get_error())")
        }
    }

    func update(data: UnsafeRawBufferPointer) {
        guard let baseAddress = data.baseAddress else {
            return
        }

        CCryptoBoringSSL_EVP_DigestUpdate(self.contextPointer, baseAddress, data.count)
    }

    // This finalize function is _destructive_: do not call it if you want to reuse the object!
    func finalize() -> [UInt8] {
        let digestSize = CCryptoBoringSSL_EVP_MD_size(self.contextPointer.pointee.digest)
        var digestBytes = Array(repeating: UInt8(0), count: digestSize)
        var count = UInt32(digestSize)

        digestBytes.withUnsafeMutableBufferPointer { digestPointer in
            assert(digestPointer.count == count)
            CCryptoBoringSSL_EVP_DigestFinal(self.contextPointer, digestPointer.baseAddress, &count)
        }

        return digestBytes
    }

    deinit {
        CCryptoBoringSSL_EVP_MD_CTX_free(self.contextPointer)
    }
}

extension DigestContext {
    struct DigestType {
        var dispatchTable: OpaquePointer

        private init(_ dispatchTable: OpaquePointer) {
            self.dispatchTable = dispatchTable
        }

        static let md5 = DigestType(CCryptoBoringSSL_EVP_md5())

        static let sha1 = DigestType(CCryptoBoringSSL_EVP_sha1())

        static let sha256 = DigestType(CCryptoBoringSSL_EVP_sha256())

        static let sha384 = DigestType(CCryptoBoringSSL_EVP_sha384())

        static let sha512 = DigestType(CCryptoBoringSSL_EVP_sha512())
    }
}
#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
