//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2022 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// An abstraction over a BoringSSL AEAD
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum BoringSSLAEAD {
    /// The supported AEAD ciphers for BoringSSL.
    case aes128gcm
    case aes192gcm
    case aes256gcm
    case aes128gcmsiv
    case aes256gcmsiv
    case chacha20
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLAEAD {
    // Arguably this class is excessive, but it's probably better for this API to be as safe as possible
    // rather than rely on defer statements for our cleanup.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public class AEADContext {
        private var context: EVP_AEAD_CTX

        public init<Key: ContiguousBytes>(cipher: BoringSSLAEAD, key: Key) throws {
            self.context = EVP_AEAD_CTX()

            let rc: CInt = key.withUnsafeBytes { keyPointer in
                withUnsafeMutablePointer(to: &self.context) { contextPointer in
                    // Create the AEAD context with a default tag length using the given key.
                    CCryptoBoringSSLShims_EVP_AEAD_CTX_init(
                        contextPointer,
                        cipher.boringSSLCipher,
                        keyPointer.baseAddress,
                        keyPointer.count,
                        0,
                        nil
                    )
                }
            }

            guard rc == 1 else {
                throw CryptoBoringWrapperError.internalBoringSSLError()
            }
        }

        deinit {
            withUnsafeMutablePointer(to: &self.context) { contextPointer in
                CCryptoBoringSSL_EVP_AEAD_CTX_cleanup(contextPointer)
            }
        }
    }
}

// MARK: - Sealing

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLAEAD.AEADContext {
    /// The main entry point for sealing data. Covers the full gamut of types, including discontiguous data types. This must be inlinable.
    public func seal<
        Plaintext: DataProtocol,
        Nonce: ContiguousBytes,
        AuthenticatedData: DataProtocol
    >(
        message: Plaintext,
        nonce: Nonce,
        authenticatedData: AuthenticatedData
    ) throws -> Data {
        // Seal is a somewhat awkward function. As it returns a Data, we are going to need to initialize a Data large enough to write into. Data does not provide us an
        // initializer that gives us access to its uninitialized memory, so the cost of creating this Data is the cost of allocating the data + the cost of initializing
        // it. For smaller plaintexts this isn't too big a deal, but for larger ones the initialization cost can really get hairy.
        //
        // We can avoid this by using Data(bytesNoCopy:deallocator:), so that's what we do. In principle we can do slightly better in the case where we have a discontiguous Plaintext
        // type, but it's honestly not worth it enough to justify the code complexity.
        switch (message.regions.count, authenticatedData.regions.count) {
        case (1, 1):
            // We can use a nice fast-path here.
            return try self._sealContiguous(
                message: message.regions.first!,
                nonce: nonce,
                authenticatedData: authenticatedData.regions.first!
            )
        case (1, _):
            let contiguousAD = Array(authenticatedData)
            return try self._sealContiguous(
                message: message.regions.first!,
                nonce: nonce,
                authenticatedData: contiguousAD
            )
        case (_, 1):
            let contiguousMessage = Array(message)
            return try self._sealContiguous(
                message: contiguousMessage,
                nonce: nonce,
                authenticatedData: authenticatedData.regions.first!
            )
        case (_, _):
            let contiguousMessage = Array(message)
            let contiguousAD = Array(authenticatedData)
            return try self._sealContiguous(
                message: contiguousMessage,
                nonce: nonce,
                authenticatedData: contiguousAD
            )
        }
    }

    /// A fast-path for sealing contiguous data. Also inlinable to gain specialization information.
    @inlinable
    func _sealContiguous<
        Plaintext: ContiguousBytes,
        Nonce: ContiguousBytes,
        AuthenticatedData: ContiguousBytes
    >(
        message: Plaintext,
        nonce: Nonce,
        authenticatedData: AuthenticatedData
    ) throws -> Data {
        try message.withUnsafeBytes { messagePointer in
            try nonce.withUnsafeBytes { noncePointer in
                try authenticatedData.withUnsafeBytes { authenticatedDataPointer in
                    try self._sealContiguous(
                        plaintext: messagePointer.bytes,
                        nonce: noncePointer.bytes,
                        authenticatedData: authenticatedDataPointer.bytes
                    )
                }
            }
        }
    }

    /// Lowest level seal operation that calls into BoringSSL directly and
    /// operates on already-allocated memory.
    #if swift(<6.3)
    @_lifetime(tag: copy tag)
    #endif
    public func seal(
        message: inout MutableRawSpan,
        nonce: RawSpan,
        authenticatedData: RawSpan,
        tag: inout OutputRawSpan
    ) throws {
        let tagByteCount = CCryptoBoringSSL_EVP_AEAD_max_overhead(self.context.aead)
        precondition(tag.freeCapacity >= tagByteCount)
        var actualTagSize = tagByteCount

        let rc = withUnsafeMutablePointer(to: &self.context) { contextPointer in
            message.withUnsafeMutableBytes { messageBuffer in
                tag.withUnsafeMutableBytes { tagBuffer, tagInitializedCount in
                    defer {
                        tagInitializedCount += actualTagSize
                    }

                    return authenticatedData.withUnsafeBytes { authenticatedDataBuffer in
                        nonce.withUnsafeBytes { nonceBuffer in
                            CCryptoBoringSSLShims_EVP_AEAD_CTX_seal_scatter(
                                contextPointer,
                                messageBuffer.baseAddress,
                                tagBuffer.baseAddress! + tagInitializedCount,
                                &actualTagSize,
                                tagBuffer.count - tagInitializedCount,
                                nonceBuffer.baseAddress,
                                nonceBuffer.count,
                                messageBuffer.baseAddress,
                                messageBuffer.count,
                                nil,
                                0,
                                authenticatedDataBuffer.baseAddress,
                                authenticatedDataBuffer.count
                            )
                        }

                    }
                }
            }
        }

        guard rc == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
    }

    /// The unsafe base call: not inlinable so that it can touch private variables.
    @usableFromInline
    func _sealContiguous(
        plaintext: RawSpan,
        nonce: RawSpan,
        authenticatedData: RawSpan
    ) throws -> Data {
        let tagByteCount = CCryptoBoringSSL_EVP_AEAD_max_overhead(self.context.aead)

        // Form the combined represention of a sealed box with nonce + plaintext + tag.
        var combined = Data()
        combined.reserveCapacity(nonce.byteCount + plaintext.byteCount + tagByteCount)
        combined.append(contentsOf: nonce)
        combined.append(contentsOf: plaintext)
        combined.append(Data(count: tagByteCount))

        try combined.withUnsafeMutableBytes { (combinedBuffer: UnsafeMutableRawBufferPointer) in
            let messageRange = nonce.byteCount..<(nonce.byteCount + plaintext.byteCount)
            let messageBuffer = UnsafeMutableRawBufferPointer(rebasing: combinedBuffer[messageRange])
            var messageSpan = messageBuffer.mutableBytes

            let tagBuffer = UnsafeMutableRawBufferPointer(
                rebasing: combinedBuffer[(nonce.byteCount + plaintext.byteCount)...]
            )
            var tagSpan = OutputRawSpan(buffer: tagBuffer, initializedCount: 0)
            try seal(
                message: &messageSpan,
                nonce: nonce,
                authenticatedData: authenticatedData,
                tag: &tagSpan
            )
            let tagBytesWritten = tagSpan.finalize(for: tagBuffer)
            assert(tagBytesWritten == tagByteCount)
        }

        return combined
    }
}

// MARK: - Opening

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLAEAD.AEADContext {
    /// The main entry point for opening data. Covers the full gamut of types, including discontiguous data types. This must be inlinable.
    @inlinable
    public func open<Nonce: ContiguousBytes, AuthenticatedData: DataProtocol>(
        ciphertext: Data,
        nonce: Nonce,
        tag: Data,
        authenticatedData: AuthenticatedData
    ) throws -> Data {
        // Open is a somewhat awkward function. As it returns a Data, we are going to need to initialize a Data large enough to write into. Data does not provide us an
        // initializer that gives us access to its uninitialized memory, so the cost of creating this Data is the cost of allocating the data + the cost of initializing
        // it. For smaller plaintexts this isn't too big a deal, but for larger ones the initialization cost can really get hairy.
        //
        // We can avoid this by using Data(bytesNoCopy:deallocator:), so that's what we do. In principle we can do slightly better in the case where we have a discontiguous Plaintext
        // type, but it's honestly not worth it enough to justify the code complexity.
        if authenticatedData.regions.count == 1 {
            // We can use a nice fast-path here.
            return try self._openContiguous(
                ciphertext: ciphertext,
                nonce: nonce,
                tag: tag,
                authenticatedData: authenticatedData.regions.first!
            )
        } else {
            let contiguousAD = Array(authenticatedData)
            return try self._openContiguous(
                ciphertext: ciphertext,
                nonce: nonce,
                tag: tag,
                authenticatedData: contiguousAD
            )
        }
    }

    /// A fast-path for opening contiguous data. Also inlinable to gain specialization information.
    @inlinable
    func _openContiguous<Nonce: ContiguousBytes, AuthenticatedData: ContiguousBytes>(
        ciphertext: Data,
        nonce: Nonce,
        tag: Data,
        authenticatedData: AuthenticatedData
    ) throws -> Data {
        try ciphertext.withUnsafeBytes { ciphertextPointer in
            try nonce.withUnsafeBytes { nonceBytes in
                try tag.withUnsafeBytes { tagBytes in
                    try authenticatedData.withUnsafeBytes { authenticatedDataBytes in
                        try self._openContiguous(
                            ciphertext: ciphertextPointer.bytes,
                            nonceBytes: nonceBytes.bytes,
                            tagBytes: tagBytes.bytes,
                            authenticatedData: authenticatedDataBytes.bytes
                        )
                    }
                }
            }
        }
    }

    /// Lowest level call into BoringSSL that decrypts in place.
    #if swift(<6.3)
    @_lifetime(message: copy message)
    #endif
    public func open(
        message: inout MutableRawSpan,
        nonce: RawSpan,
        tag: RawSpan,
        authenticatedData: RawSpan
    ) throws {
        let rc = withUnsafePointer(to: &self.context) { contextPointer in
            message.withUnsafeMutableBytes { messageBuffer in
                nonce.withUnsafeBytes { nonceBuffer in
                    tag.withUnsafeBytes { tagBuffer in
                        authenticatedData.withUnsafeBytes { adBuffer in
                            CCryptoBoringSSLShims_EVP_AEAD_CTX_open_gather(
                                contextPointer,
                                messageBuffer.baseAddress,
                                nonceBuffer.baseAddress,
                                nonceBuffer.count,
                                messageBuffer.baseAddress,
                                messageBuffer.count,
                                tagBuffer.baseAddress,
                                tagBuffer.count,
                                adBuffer.baseAddress,
                                adBuffer.count
                            )
                        }
                    }
                }
            }
        }

        guard rc == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
    }

    /// The unsafe base call: not inlinable so that it can touch private variables.
    @usableFromInline
    func _openContiguous(
        ciphertext: RawSpan,
        nonceBytes: RawSpan,
        tagBytes: RawSpan,
        authenticatedData: RawSpan
    ) throws -> Data {
        var output = Data(copying: ciphertext)
        if #available(visionOS 1.1, *) {
            var outputSpan = output.mutableBytes
            try open(message: &outputSpan, nonce: nonceBytes, tag: tagBytes, authenticatedData: authenticatedData)
        } else {
            // For some reason `Data.mutableBytes` is not available on visionOS 1.0 so we'll bounce through wUSMB.
            try output.withUnsafeMutableBytes { bytes in
                var outputSpan = bytes.mutableBytes
                try open(message: &outputSpan, nonce: nonceBytes, tag: tagBytes, authenticatedData: authenticatedData)
            }
        }
        return output
    }

    /// An additional entry point for opening data where the ciphertext and the tag can be provided as one combined data . Covers the full gamut of types, including discontiguous data types. This must be inlinable.
    @inlinable
    public func open<Nonce: ContiguousBytes, AuthenticatedData: DataProtocol>(
        combinedCiphertextAndTag: Data,
        nonce: Nonce,
        authenticatedData: AuthenticatedData
    ) throws -> Data {
        // Open is a somewhat awkward function. As it returns a Data, we are going to need to initialize a Data large enough to write into. Data does not provide us an
        // initializer that gives us access to its uninitialized memory, so the cost of creating this Data is the cost of allocating the data + the cost of initializing
        // it. For smaller plaintexts this isn't too big a deal, but for larger ones the initialization cost can really get hairy.
        //
        // We can avoid this by using Data(bytesNoCopy:deallocator:), so that's what we do. In principle we can do slightly better in the case where we have a discontiguous Plaintext
        // type, but it's honestly not worth it enough to justify the code complexity.
        if authenticatedData.regions.count == 1 {
            // We can use a nice fast-path here.
            return try self._openContiguous(
                combinedCiphertextAndTag: combinedCiphertextAndTag,
                nonce: nonce,
                authenticatedData: authenticatedData.regions.first!
            )
        } else {
            let contiguousAD = Array(authenticatedData)
            return try self._openContiguous(
                combinedCiphertextAndTag: combinedCiphertextAndTag,
                nonce: nonce,
                authenticatedData: contiguousAD
            )
        }
    }

    /// A fast-path for opening contiguous data. Also inlinable to gain specialization information.
    @inlinable
    func _openContiguous<Nonce: ContiguousBytes, AuthenticatedData: ContiguousBytes>(
        combinedCiphertextAndTag: Data,
        nonce: Nonce,
        authenticatedData: AuthenticatedData
    ) throws -> Data {
        try combinedCiphertextAndTag.withUnsafeBytes { combinedCiphertextAndTagPointer in
            try nonce.withUnsafeBytes { nonceBytes in
                try authenticatedData.withUnsafeBytes { authenticatedDataBytes in
                    try self._openContiguous(
                        combinedCiphertextAndTag: combinedCiphertextAndTagPointer,
                        nonceBytes: nonceBytes,
                        authenticatedData: authenticatedDataBytes
                    )
                }
            }
        }
    }

    /// The unsafe base call: not inlinable so that it can touch private variables.
    @usableFromInline
    func _openContiguous(
        combinedCiphertextAndTag: UnsafeRawBufferPointer,
        nonceBytes: UnsafeRawBufferPointer,
        authenticatedData: UnsafeRawBufferPointer
    ) throws -> Data {
        // We use malloc here because we are going to call free later. We force unwrap to trigger crashes if the allocation
        // fails.
        let outputBuffer = UnsafeMutableRawBufferPointer(
            start: malloc(combinedCiphertextAndTag.count)!,
            count: combinedCiphertextAndTag.count
        )

        var writtenBytes = 0
        let rc = withUnsafePointer(to: &self.context) { contextPointer in
            CCryptoBoringSSLShims_EVP_AEAD_CTX_open(
                contextPointer,
                outputBuffer.baseAddress,
                &writtenBytes,
                outputBuffer.count,
                nonceBytes.baseAddress,
                nonceBytes.count,
                combinedCiphertextAndTag.baseAddress,
                combinedCiphertextAndTag.count,
                authenticatedData.baseAddress,
                authenticatedData.count
            )
        }

        guard rc == 1 else {
            // Ooops, error. Free the memory we allocated before we throw.
            free(outputBuffer.baseAddress)
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        let output = Data(
            bytesNoCopy: outputBuffer.baseAddress!,
            count: outputBuffer.count,
            deallocator: .free
        ).prefix(writtenBytes)
        return output
    }

}

// MARK: - Supported ciphers

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLAEAD {
    var boringSSLCipher: OpaquePointer {
        switch self {
        case .aes128gcm:
            return CCryptoBoringSSL_EVP_aead_aes_128_gcm()
        case .aes192gcm:
            return CCryptoBoringSSL_EVP_aead_aes_192_gcm()
        case .aes256gcm:
            return CCryptoBoringSSL_EVP_aead_aes_256_gcm()
        case .aes128gcmsiv:
            return CCryptoBoringSSL_EVP_aead_aes_128_gcm_siv()
        case .aes256gcmsiv:
            return CCryptoBoringSSL_EVP_aead_aes_256_gcm_siv()
        case .chacha20:
            return CCryptoBoringSSL_EVP_aead_chacha20_poly1305()
        }
    }
}
