//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol HashFunctionImplementationDetails: HashFunction where Digest: DigestPrivate {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol BoringSSLBackedHashFunction: HashFunctionImplementationDetails {
    associatedtype Context
    static var digestSize: Int { get }
    static func initialize() -> Context?
    static func update(_ context: inout Context, data: UnsafeRawBufferPointer) -> Bool
    static func finalize(_ context: inout Context, digest: UnsafeMutableRawBufferPointer) -> Bool
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Insecure.MD5: BoringSSLBackedHashFunction {
    static var digestSize: Int {
        Int(MD5_DIGEST_LENGTH)
    }

    static func initialize() -> MD5_CTX? {
        var context = MD5_CTX()
        guard CCryptoBoringSSL_MD5_Init(&context) == 1 else {
            return nil
        }
        return context
    }

    static func update(_ context: inout MD5_CTX, data: UnsafeRawBufferPointer) -> Bool {
        CCryptoBoringSSL_MD5_Update(&context, data.baseAddress, data.count) == 1
    }

    static func finalize(_ context: inout MD5_CTX, digest: UnsafeMutableRawBufferPointer) -> Bool {
        guard let baseAddress = digest.baseAddress, digest.count == Self.digestSize else { return false }
        return CCryptoBoringSSL_MD5_Final(baseAddress, &context) == 1
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Insecure.SHA1: BoringSSLBackedHashFunction {
    static var digestSize: Int {
        Int(SHA_DIGEST_LENGTH)
    }

    static func initialize() -> SHA_CTX? {
        var context = SHA_CTX()
        guard CCryptoBoringSSL_SHA1_Init(&context) == 1 else {
            return nil
        }
        return context
    }

    static func update(_ context: inout SHA_CTX, data: UnsafeRawBufferPointer) -> Bool {
        CCryptoBoringSSL_SHA1_Update(&context, data.baseAddress, data.count) == 1
    }

    static func finalize(_ context: inout SHA_CTX, digest: UnsafeMutableRawBufferPointer) -> Bool {
        guard let baseAddress = digest.baseAddress, digest.count == Self.digestSize else { return false }
        return CCryptoBoringSSL_SHA1_Final(baseAddress, &context) == 1
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SHA256: BoringSSLBackedHashFunction {
    static var digestSize: Int {
        Int(SHA256_DIGEST_LENGTH)
    }

    static func initialize() -> SHA256_CTX? {
        var context = SHA256_CTX()
        guard CCryptoBoringSSL_SHA256_Init(&context) == 1 else {
            return nil
        }
        return context
    }

    static func update(_ context: inout SHA256_CTX, data: UnsafeRawBufferPointer) -> Bool {
        CCryptoBoringSSL_SHA256_Update(&context, data.baseAddress, data.count) == 1
    }

    static func finalize(_ context: inout SHA256_CTX, digest: UnsafeMutableRawBufferPointer) -> Bool {
        guard let baseAddress = digest.baseAddress, digest.count == Self.digestSize else { return false }
        return CCryptoBoringSSL_SHA256_Final(baseAddress, &context) == 1
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SHA384: BoringSSLBackedHashFunction {
    static var digestSize: Int {
        Int(SHA384_DIGEST_LENGTH)
    }

    static func initialize() -> SHA512_CTX? {
        var context = SHA512_CTX()
        guard CCryptoBoringSSL_SHA384_Init(&context) == 1 else {
            return nil
        }
        return context
    }

    static func update(_ context: inout SHA512_CTX, data: UnsafeRawBufferPointer) -> Bool {
        CCryptoBoringSSL_SHA384_Update(&context, data.baseAddress, data.count) == 1
    }

    static func finalize(_ context: inout SHA512_CTX, digest: UnsafeMutableRawBufferPointer) -> Bool {
        guard let baseAddress = digest.baseAddress, digest.count == Self.digestSize else { return false }
        return CCryptoBoringSSL_SHA384_Final(baseAddress, &context) == 1
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SHA512: BoringSSLBackedHashFunction {
    static var digestSize: Int {
        Int(SHA512_DIGEST_LENGTH)
    }

    static func initialize() -> SHA512_CTX? {
        var context = SHA512_CTX()
        guard CCryptoBoringSSL_SHA512_Init(&context) == 1 else {
            return nil
        }
        return context
    }

    static func update(_ context: inout SHA512_CTX, data: UnsafeRawBufferPointer) -> Bool {
        CCryptoBoringSSL_SHA512_Update(&context, data.baseAddress, data.count) == 1
    }

    static func finalize(_ context: inout SHA512_CTX, digest: UnsafeMutableRawBufferPointer) -> Bool {
        guard let baseAddress = digest.baseAddress, digest.count == Self.digestSize else { return false }
        return CCryptoBoringSSL_SHA512_Final(baseAddress, &context) == 1
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct OpenSSLDigestImpl<H: BoringSSLBackedHashFunction>: @unchecked Sendable {
    private var context: DigestContext<H>

    init() {
        self.context = DigestContext()
    }

    internal mutating func update(data: UnsafeRawBufferPointer) {
        if !isKnownUniquelyReferenced(&self.context) {
            self.context = DigestContext(copying: self.context)
        }
        self.context.update(data: data)
    }

    internal func finalize() -> H.Digest {
        self.context.finalize()
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
private final class DigestContext<H: BoringSSLBackedHashFunction> {
    private var context: H.Context

    init() {
        guard let contex = H.initialize() else {
            preconditionFailure("Unable to initialize digest state")
        }
        self.context = contex
    }

    init(copying original: DigestContext) {
        self.context = original.context
    }

    func update(data: UnsafeRawBufferPointer) {
        guard H.update(&self.context, data: data) else {
            preconditionFailure("Unable to update digest state")
        }
    }

    func finalize() -> H.Digest {
        var copyContext = self.context
        defer {
            withUnsafeMutablePointer(to: &copyContext) { $0.zeroize() }
        }
        return withUnsafeTemporaryAllocation(byteCount: H.digestSize, alignment: 1) { digestPointer in
            defer {
                digestPointer.zeroize()
            }
            guard H.finalize(&copyContext, digest: digestPointer) else {
                preconditionFailure("Unable to finalize digest state")
            }
            // We force unwrap here because if the digest size is wrong it's an internal error.
            return H.Digest(bufferPointer: UnsafeRawBufferPointer(digestPointer))!
        }
    }

    deinit {
        withUnsafeMutablePointer(to: &self.context) { $0.zeroize() }
    }
}
#endif  // CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
