//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2025 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// Derived from swift-nio's ThreadSpecificVariable type.

/// A ``ThreadSpecificVariable`` is a variable that can be read and set like a normal variable except that it holds
/// different variables per thread.
///
/// ``ThreadSpecificVariable`` is thread-safe so it can be used with multiple threads at the same time but the value
/// returned by ``currentValue`` is defined per thread.
///
/// - Note: Though ``ThreadSpecificVariable`` is thread-safe, it is not `Sendable` unless `Value` is `Sendable`.
///     If ``ThreadSpecificVariable`` were unconditionally `Sendable`, it could be used to "smuggle"
///     non-`Sendable` state out of an actor or other isolation domain without triggering warnings. If you
///     are attempting to use ``ThreadSpecificVariable`` with non-`Sendable` data, consider using a dynamic
///     enforcement tool like `NIOLoopBoundBox` to police the access.
final class ThreadSpecificVariable<Value: AnyObject> {
    // the actual type in there is `Box<(ThreadSpecificVariable<T>, T)>` but we can't use that as C functions can't capture (even types)
    private typealias BoxedType = Box<(AnyObject, AnyObject)>

    private class Key {
        private var underlyingKey: ThreadOpsSystem.ThreadSpecificKey

        internal init(destructor: @escaping ThreadOpsSystem.ThreadSpecificKeyDestructor) {
            self.underlyingKey = ThreadOpsSystem.allocateThreadSpecificValue(destructor: destructor)
        }

        deinit {
            ThreadOpsSystem.deallocateThreadSpecificValue(self.underlyingKey)
        }

        func get() -> UnsafeMutableRawPointer? {
            ThreadOpsSystem.getThreadSpecificValue(self.underlyingKey)
        }

        func set(value: UnsafeMutableRawPointer?) {
            ThreadOpsSystem.setThreadSpecificValue(key: self.underlyingKey, value: value)
        }
    }

    private let key: Key

    /// Initialize a new `ThreadSpecificVariable` without a current value (`currentValue == nil`).
    init() {
        self.key = Key(destructor: {
            Unmanaged<BoxedType>.fromOpaque(($0 as UnsafeMutableRawPointer?)!).release()
        })
    }

    /// Initialize a new `ThreadSpecificVariable` with `value` for the calling thread. After calling this, the calling
    /// thread will see `currentValue == value` but on all other threads `currentValue` will be `nil` until changed.
    ///
    /// - Parameters:
    ///   - value: The value to set for the calling thread.
    convenience init(value: Value) {
        self.init()
        self.currentValue = value
    }

    /// The value for the current thread.
    @available(
        *,
        noasync,
        message: "threads can change between suspension points and therefore the thread specific value too"
    )
    var currentValue: Value? {
        get {
            self.get()
        }
        set {
            self.set(newValue)
        }
    }

    /// Get the current value for the calling thread.
    private func get() -> Value? {
        guard let raw = self.key.get() else { return nil }
        // parenthesize the return value to silence the cast warning
        return
            (Unmanaged<BoxedType>
            .fromOpaque(raw)
            .takeUnretainedValue()
            .value.1 as! Value)
    }

    /// Set the current value for the calling threads. The `currentValue` for all other threads remains unchanged.
    private func set(_ newValue: Value?) {
        if let raw = self.key.get() {
            Unmanaged<BoxedType>.fromOpaque(raw).release()
        }
        self.key.set(value: newValue.map { Unmanaged.passRetained(Box((self, $0))).toOpaque() })
    }
}

extension ThreadSpecificVariable: @unchecked Sendable where Value: Sendable {}

final class Box<T> {
    let value: T
    init(_ value: T) { self.value = value }
}
