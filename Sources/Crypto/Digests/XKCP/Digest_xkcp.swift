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
@_implementationOnly import CXKCP
@_implementationOnly import CXKCPShims

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol XKCPBackedHashFunction: HashFunctionImplementationDetails {
    associatedtype Context
    static var digestSize: Int { get }
    static func initialize() -> Context?
    static func update(_ context: inout Context, data: UnsafeRawBufferPointer) -> Bool
    static func finalize(_ context: inout Context, digest: UnsafeMutableRawBufferPointer) -> Bool
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SHA3_256: XKCPBackedHashFunction {
    static var digestSize: Int { 32 }

    static func initialize() -> Keccak_HashInstance? {
        var context = Keccak_HashInstance()
        guard CXKCPShims_Keccak_HashInitialize_SHA3_256(&context) == KECCAK_SUCCESS else {
            return nil
        }
        return context
    }

    static func update(_ context: inout Keccak_HashInstance, data: UnsafeRawBufferPointer) -> Bool {
        guard let baseAddress = data.baseAddress else { return true }
        return Keccak_HashUpdate(&context, baseAddress, data.count * 8) == KECCAK_SUCCESS
    }

    static func finalize(_ context: inout Keccak_HashInstance, digest: UnsafeMutableRawBufferPointer) -> Bool {
        guard let baseAddress = digest.baseAddress, digest.count == Self.digestSize else { return false }
        return Keccak_HashFinal(&context, baseAddress) == KECCAK_SUCCESS
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SHA3_384: XKCPBackedHashFunction {
    static var digestSize: Int { 48 }

    static func initialize() -> Keccak_HashInstance? {
        var context = Keccak_HashInstance()
        guard CXKCPShims_Keccak_HashInitialize_SHA3_384(&context) == KECCAK_SUCCESS else {
            return nil
        }
        return context
    }

    static func update(_ context: inout Keccak_HashInstance, data: UnsafeRawBufferPointer) -> Bool {
        guard let baseAddress = data.baseAddress else { return true }
        return Keccak_HashUpdate(&context, baseAddress, data.count * 8) == KECCAK_SUCCESS
    }

    static func finalize(_ context: inout Keccak_HashInstance, digest: UnsafeMutableRawBufferPointer) -> Bool {
        guard let baseAddress = digest.baseAddress, digest.count == Self.digestSize else { return false }
        return Keccak_HashFinal(&context, baseAddress) == KECCAK_SUCCESS
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SHA3_512: XKCPBackedHashFunction {
    static var digestSize: Int { 64 }

    static func initialize() -> Keccak_HashInstance? {
        var context = Keccak_HashInstance()
        guard CXKCPShims_Keccak_HashInitialize_SHA3_512(&context) == KECCAK_SUCCESS else {
            return nil
        }
        return context
    }

    static func update(_ context: inout Keccak_HashInstance, data: UnsafeRawBufferPointer) -> Bool {
        guard let baseAddress = data.baseAddress else { return true }
        return Keccak_HashUpdate(&context, baseAddress, data.count * 8) == KECCAK_SUCCESS
    }

    static func finalize(_ context: inout Keccak_HashInstance, digest: UnsafeMutableRawBufferPointer) -> Bool {
        guard let baseAddress = digest.baseAddress, digest.count == Self.digestSize else { return false }
        return Keccak_HashFinal(&context, baseAddress) == KECCAK_SUCCESS
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct XKCPDigestImpl<H: XKCPBackedHashFunction>: @unchecked Sendable {
    private var context: XKCPDigestContext<H>

    init() {
        self.context = XKCPDigestContext()
    }

    internal mutating func update(data: UnsafeRawBufferPointer) {
        if !isKnownUniquelyReferenced(&self.context) {
            self.context = XKCPDigestContext(copying: self.context)
        }
        self.context.update(data: data)
    }

    internal func finalize() -> H.Digest {
        self.context.finalize()
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
private final class XKCPDigestContext<H: XKCPBackedHashFunction> {
    private var context: H.Context

    init() {
        guard let context = H.initialize() else {
            preconditionFailure("Unable to initialize digest state")
        }
        self.context = context
    }

    init(copying original: XKCPDigestContext) {
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
