//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftOpenAPIGenerator open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftOpenAPIGenerator project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftOpenAPIGenerator project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if canImport(Darwin)

import Foundation

/// Revends an array as an async sequence, one element at a time, with an optional manual trigger.
struct MockAsyncSequence<Element>: AsyncSequence, Sendable where Element: Sendable {
    var elementsToVend: [Element]
    private let _elementsVended: LockedValueBox<[Element]>
    var elementsVended: [Element] { _elementsVended.withValue { $0 } }
    private let semaphore: DispatchSemaphore?

    init(elementsToVend: [Element], gatingProduction: Bool) {
        self.elementsToVend = elementsToVend
        self._elementsVended = LockedValueBox([])
        self.semaphore = gatingProduction ? DispatchSemaphore(value: 0) : nil
    }

    func openGate(for count: Int) { for _ in 0..<count { semaphore?.signal() } }

    func openGate() {
        openGate(for: elementsToVend.count + 1)  // + 1 for the nil
    }

    func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(elementsToVend: elementsToVend[...], semaphore: semaphore, elementsVended: _elementsVended)
    }

    final class AsyncIterator: AsyncIteratorProtocol {
        var elementsToVend: ArraySlice<Element>
        var semaphore: DispatchSemaphore?
        var elementsVended: LockedValueBox<[Element]>

        init(
            elementsToVend: ArraySlice<Element>,
            semaphore: DispatchSemaphore?,
            elementsVended: LockedValueBox<[Element]>
        ) {
            self.elementsToVend = elementsToVend
            self.semaphore = semaphore
            self.elementsVended = elementsVended
        }

        func next() async throws -> Element? {
            await withCheckedContinuation { continuation in
                semaphore?.wait()
                continuation.resume()
            }
            guard let element = elementsToVend.popFirst() else { return nil }
            elementsVended.withValue { $0.append(element) }
            return element
        }
    }
}

#endif  // #if canImport(Darwin)
