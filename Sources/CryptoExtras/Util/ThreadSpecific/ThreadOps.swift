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
// Copyright (c) 2017-2014 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
protocol ThreadOps {
    associatedtype ThreadSpecificKey
    associatedtype ThreadSpecificKeyDestructor

    static func allocateThreadSpecificValue(destructor: ThreadSpecificKeyDestructor) -> ThreadSpecificKey
    static func deallocateThreadSpecificValue(_ key: ThreadSpecificKey)
    static func getThreadSpecificValue(_ key: ThreadSpecificKey) -> UnsafeMutableRawPointer?
    static func setThreadSpecificValue(key: ThreadSpecificKey, value: UnsafeMutableRawPointer?)
}
