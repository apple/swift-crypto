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
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if os(Linux) || os(Android) || os(FreeBSD) || os(OpenBSD) || canImport(Darwin)
#if canImport(Glibc)
@preconcurrency import Glibc
#elseif canImport(Bionic)
@preconcurrency import Bionic
#elseif canImport(Musl)
@preconcurrency import Musl
#elseif canImport(Android)
@preconcurrency import Android
#elseif canImport(Darwin)
import Darwin
#endif

typealias ThreadOpsSystem = ThreadOpsPosix

enum ThreadOpsPosix: ThreadOps {
    typealias ThreadSpecificKey = pthread_key_t
    #if canImport(Darwin)
    typealias ThreadSpecificKeyDestructor = @convention(c) (UnsafeMutableRawPointer) -> Void
    #else
    typealias ThreadSpecificKeyDestructor = @convention(c) (UnsafeMutableRawPointer?) -> Void
    #endif

    static func allocateThreadSpecificValue(destructor: @escaping ThreadSpecificKeyDestructor) -> ThreadSpecificKey {
        var value = pthread_key_t()
        let result = pthread_key_create(&value, Optional(destructor))
        precondition(result == 0, "pthread_key_create failed: \(result)")
        return value
    }

    static func deallocateThreadSpecificValue(_ key: ThreadSpecificKey) {
        let result = pthread_key_delete(key)
        precondition(result == 0, "pthread_key_delete failed: \(result)")
    }

    static func getThreadSpecificValue(_ key: ThreadSpecificKey) -> UnsafeMutableRawPointer? {
        pthread_getspecific(key)
    }

    static func setThreadSpecificValue(key: ThreadSpecificKey, value: UnsafeMutableRawPointer?) {
        let result = pthread_setspecific(key, value)
        precondition(result == 0, "pthread_setspecific failed: \(result)")
    }
}

#endif
