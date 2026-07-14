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

import Crypto

#if hasFeature(SourceWarningControl)
@diagnose(ImplementationOnlyDeprecated, as: ignored) @_implementationOnly import CCryptoBoringSSL
#else
@_implementationOnly import CCryptoBoringSSL
#endif

#if canImport(Darwin)
import Darwin
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
final class BoringSSLSHA512256Context {
    // @_implementationOnly import => must use OpaquePointer for stored property.
    private let _storage: OpaquePointer
    private var context: UnsafeMutablePointer<SHA512_CTX> {
        UnsafeMutablePointer(self._storage)
    }

    /// This is the only designated initializer, responsible for the allocation. Deallocation happens in deinit.
    /// To reduce mistakes (e.g. double-free), all other initializers should be convenience initializers.
    private init(takingOwnershipOf pointer: UnsafeMutablePointer<SHA512_CTX>) {
        self._storage = OpaquePointer(pointer)
    }

    deinit {
        self.context.zeroize()
        self.context.deinitialize(count: 1)
        self.context.deallocate()
    }

    convenience init() {
        let ptr = UnsafeMutablePointer<SHA512_CTX>.allocate(capacity: 1)
        ptr.initialize(to: SHA512_CTX())
        self.init(takingOwnershipOf: ptr)

        guard CCryptoBoringSSL_SHA512_256_Init(self.context) == 1 else {
            preconditionFailure("Unable to initialize digest state")
        }
    }

    convenience init(copying original: BoringSSLSHA512256Context) {
        let ptr = UnsafeMutablePointer<SHA512_CTX>.allocate(capacity: 1)
        ptr.initialize(to: original.context.pointee)
        self.init(takingOwnershipOf: ptr)
    }

    func update(bufferPointer data: UnsafeRawBufferPointer) {
        guard CCryptoBoringSSL_SHA512_256_Update(self.context, data.baseAddress, data.count) == 1 else {
            preconditionFailure("Unable to update digest state")
        }
    }

    func finalize() -> SHA512256Digest {
        var contextCopy = self.context.pointee
        defer { withUnsafeMutablePointer(to: &contextCopy) { $0.zeroize() } }
        return withUnsafeTemporaryAllocation(byteCount: SHA512256Digest.byteCount, alignment: 1) { digestPointer in
            guard CCryptoBoringSSL_SHA512_256_Final(digestPointer.baseAddress, &contextCopy) == 1 else {
                preconditionFailure("Unable to finalize digest state")
            }
            // We force unwrap here because if the digest size is wrong it's an internal error.
            return SHA512256Digest(bufferPointer: UnsafeRawBufferPointer(digestPointer))!
        }
    }
}

extension UnsafeMutablePointer {
    fileprivate func zeroize() {
        let size = MemoryLayout.size(ofValue: Pointee.self)
        memset_s(self, size, 0, size)
    }
}

extension UnsafeMutableRawBufferPointer {
    fileprivate func zeroize() {
        memset_s(self.baseAddress!, self.count, 0, self.count)
    }
}
