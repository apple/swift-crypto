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

#if canImport(Darwin)
import Darwin
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
final class BoringSSLSHA512256Context {
    private var context: SHA512_CTX

    init() {
        guard let context = BoringSSLSHA512256HashFunction.initialize() else {
            preconditionFailure("Unable to initialize digest state")
        }
        self.context = context
    }

    deinit {
        withUnsafeMutablePointer(to: &self.context) {
            $0.zeroize()
        }
    }

    init(copying original: BoringSSLSHA512256Context) {
        self.context = original.context
    }

    func update(bufferPointer data: UnsafeRawBufferPointer) {
        guard BoringSSLSHA512256HashFunction.update(&self.context, data: data) else {
            preconditionFailure("Unable to update digest state")
        }
    }

    func finalize() -> SHA512256Digest {
        var copyContext = self.context
        defer {
            withUnsafeMutablePointer(to: &copyContext) {
                $0.zeroize()
            }
        }
        return withUnsafeTemporaryAllocation(byteCount: BoringSSLSHA512256HashFunction.digestSize, alignment: 1) {
            digestPointer in
            defer {
                digestPointer.zeroize()
            }

            guard BoringSSLSHA512256HashFunction.finalize(&copyContext, digest: digestPointer) else {
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
