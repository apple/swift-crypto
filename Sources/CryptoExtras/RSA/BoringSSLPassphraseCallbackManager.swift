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

/// An internal protocol that exists to let us avoid problems with generic types.
///
/// The issue we have here is that we want to allow users to use whatever collection type suits them best to set
/// the passphrase. For this reason, ``_RSA/Signing/PrivateKey/PassphraseSetter`` is a generic function, generic over the `Collection`
/// protocol. However, that causes us an issue, because we need to stuff that callback into a
/// ``BoringSSLPassphraseCallbackManager`` in order to create an `Unmanaged` and round-trip the pointer through C code.
///
/// That makes ``BoringSSLPassphraseCallbackManager`` a generic object, and now we're in *real* trouble, because
/// `Unmanaged` requires us to specify the *complete* type of the object we want to unwrap. In this case, we
/// don't know it, because it's generic!
///
/// Our way out is to note that while the class itself is generic, the only function we want to call in the
/// ``globalBoringSSLPassphraseCallback`` is not. Thus, rather than try to hold the actual specific ``BoringSSLPassphraseCallbackManager``,
/// we can hold it inside a protocol existential instead, so long as that protocol existential gives us the correct
/// function to call. Hence: ``CallbackManagerProtocol``, a private protocol with a single conforming type.
internal protocol CallbackManagerProtocol: AnyObject {
    func invoke(buffer: UnsafeMutableBufferPointer<CChar>) -> CInt
}

/// This class exists primarily to work around the fact that Swift does not let us stuff
/// a closure into an `Unmanaged`. Instead, we use this object to keep hold of it.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
final class BoringSSLPassphraseCallbackManager<Bytes: Collection>: CallbackManagerProtocol
where Bytes.Element == UInt8 {
    private let userCallback: _RSA.Signing.PrivateKey.PassphraseCallback<Bytes>

    init(userCallback: @escaping _RSA.Signing.PrivateKey.PassphraseCallback<Bytes>) {
        // We have to type-erase this.
        self.userCallback = userCallback
    }

    func invoke(buffer: UnsafeMutableBufferPointer<CChar>) -> CInt {
        var count: CInt = 0

        do {
            try self.userCallback { passphraseBytes in
                // If we don't have enough space for the passphrase plus NUL, bail out.
                guard passphraseBytes.count < buffer.count else { return }
                _ = buffer.initialize(from: passphraseBytes.lazy.map { CChar($0) })
                count = CInt(passphraseBytes.count)

                // We need to add a NUL terminator, in case the user did not.
                buffer[Int(passphraseBytes.count)] = 0
            }
        } catch {
            // If we hit an error here, we just need to tolerate it. We'll return zero-length.
            count = 0
        }

        return count
    }
}

/// Our global static BoringSSL passphrase callback. This is used as a thunk to dispatch out to
/// the user-provided callback.
func globalBoringSSLPassphraseCallback(
    buf: UnsafeMutablePointer<CChar>?,
    size: CInt,
    rwflag: CInt,
    u: UnsafeMutableRawPointer?
) -> CInt {
    guard let buffer = buf, let userData = u else {
        preconditionFailure(
            "Invalid pointers passed to passphrase callback, buf: \(String(describing: buf)) u: \(String(describing: u))"
        )
    }
    let bufferPointer = UnsafeMutableBufferPointer(start: buffer, count: Int(size))
    guard let cbManager = Unmanaged<AnyObject>.fromOpaque(userData).takeUnretainedValue() as? CallbackManagerProtocol
    else {
        preconditionFailure("Failed to pass object that can handle callback")
    }
    return cbManager.invoke(buffer: bufferPointer)
}
