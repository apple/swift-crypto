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
    private let gateOpeningsStream: AsyncStream<Void>
    private let gateOpeningsContinuation: AsyncStream<Void>.Continuation

    init(elementsToVend: [Element], gatingProduction: Bool) {
        self.elementsToVend = elementsToVend
        self._elementsVended = LockedValueBox([])
        (self.gateOpeningsStream, self.gateOpeningsContinuation) = AsyncStream.makeStream(of: Void.self)
        if !gatingProduction { openGate() }
    }

    func openGate(for count: Int) { for _ in 0..<count { self.gateOpeningsContinuation.yield() } }

    func openGate() {
        openGate(for: elementsToVend.count + 1)  // + 1 for the nil
    }

    func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(
            elementsToVend: elementsToVend[...],
            gateOpenings: gateOpeningsStream.makeAsyncIterator(),
            elementsVended: _elementsVended
        )
    }

    final class AsyncIterator: AsyncIteratorProtocol {
        var elementsToVend: ArraySlice<Element>
        var gateOpenings: AsyncStream<Void>.Iterator
        var elementsVended: LockedValueBox<[Element]>

        init(
            elementsToVend: ArraySlice<Element>,
            gateOpenings: AsyncStream<Void>.Iterator,
            elementsVended: LockedValueBox<[Element]>
        ) {
            self.elementsToVend = elementsToVend
            self.gateOpenings = gateOpenings
            self.elementsVended = elementsVended
        }

        func next() async throws -> Element? {
            guard await gateOpenings.next() != nil else { throw CancellationError() }
            guard let element = elementsToVend.popFirst() else { return nil }
            elementsVended.withValue { $0.append(element) }
            return element
        }
    }
}

#endif  // #if canImport(Darwin)
