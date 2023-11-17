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
//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2020-2021 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//
import XCTest
@testable import OpenAPIURLSession

final class AsyncBackpressuredStreamTests: XCTestCase {
    func testYield() async throws {
        let (stream, source) = AsyncBackpressuredStream.makeStream(
            of: Int.self,
            backPressureStrategy: .highLowWatermark(lowWatermark: 5, highWatermark: 10)
        )

        try await source.asyncWrite(contentsOf: [1, 2, 3, 4, 5, 6])
        source.finish(throwing: nil)

        let result = try await stream.collect()
        XCTAssertEqual(result, [1, 2, 3, 4, 5, 6])
    }

    func testBackPressure() async throws {
        let (stream, source) = AsyncBackpressuredStream.makeStream(
            of: Int.self,
            backPressureStrategy: .highLowWatermark(lowWatermark: 2, highWatermark: 4)
        )

        let (backPressureEventStream, backPressureEventContinuation) = AsyncStream.makeStream(of: Void.self)

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                while true {
                    backPressureEventContinuation.yield(())
                    print("Yielding")
                    try await source.asyncWrite(contentsOf: [1])
                }
            }

            var backPressureEventIterator = backPressureEventStream.makeAsyncIterator()
            var iterator = stream.makeAsyncIterator()

            await backPressureEventIterator.next()
            await backPressureEventIterator.next()
            await backPressureEventIterator.next()
            await backPressureEventIterator.next()

            print("Waited 4 times")

            _ = try await iterator.next()
            _ = try await iterator.next()
            _ = try await iterator.next()
            print("Consumed three")

            await backPressureEventIterator.next()
            await backPressureEventIterator.next()
            await backPressureEventIterator.next()

            group.cancelAll()
        }
    }

    func testBackPressureSync() async throws {
        let (stream, source) = AsyncBackpressuredStream.makeStream(
            of: Int.self,
            backPressureStrategy: .highLowWatermark(lowWatermark: 2, highWatermark: 4)
        )

        let (backPressureEventStream, backPressureEventContinuation) = AsyncStream.makeStream(of: Void.self)

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                @Sendable func yield() {
                    backPressureEventContinuation.yield(())
                    print("Yielding")
                    source.write(contentsOf: [1]) { result in
                        switch result {
                        case .success: yield()

                        case .failure: print("Stopping to yield")
                        }
                    }
                }

                yield()
            }

            var backPressureEventIterator = backPressureEventStream.makeAsyncIterator()
            var iterator = stream.makeAsyncIterator()

            await backPressureEventIterator.next()
            await backPressureEventIterator.next()
            await backPressureEventIterator.next()
            await backPressureEventIterator.next()

            print("Waited 4 times")

            _ = try await iterator.next()
            _ = try await iterator.next()
            _ = try await iterator.next()
            print("Consumed three")

            await backPressureEventIterator.next()
            await backPressureEventIterator.next()
            await backPressureEventIterator.next()

            group.cancelAll()
        }
    }

    func testWatermarkBackPressureStrategy() async throws {
        typealias Strategy = AsyncBackpressuredStream<String, any Error>.HighLowWatermarkBackPressureStrategy
        var strategy = Strategy(lowWatermark: 2, highWatermark: 3)

        XCTAssertEqual(strategy.currentWatermark, 0)
        XCTAssertEqual(strategy.didYield(elements: Slice([])), true)
        XCTAssertEqual(strategy.currentWatermark, 0)
        XCTAssertEqual(strategy.didYield(elements: Slice(["*", "*"])), true)
        XCTAssertEqual(strategy.currentWatermark, 2)
        XCTAssertEqual(strategy.didYield(elements: Slice(["*"])), false)
        XCTAssertEqual(strategy.currentWatermark, 3)
        XCTAssertEqual(strategy.didYield(elements: Slice(["*"])), false)
        XCTAssertEqual(strategy.currentWatermark, 4)

        XCTAssertEqual(strategy.currentWatermark, 4)
        XCTAssertEqual(strategy.didConsume(elements: Slice([])), false)
        XCTAssertEqual(strategy.currentWatermark, 4)
        XCTAssertEqual(strategy.didConsume(elements: Slice(["*", "*"])), false)
        XCTAssertEqual(strategy.currentWatermark, 2)
        XCTAssertEqual(strategy.didConsume(elements: Slice(["*"])), true)
        XCTAssertEqual(strategy.currentWatermark, 1)
        XCTAssertEqual(strategy.didConsume(elements: Slice(["*"])), true)
        XCTAssertEqual(strategy.currentWatermark, 0)
        XCTAssertEqual(strategy.didConsume(elements: Slice([])), true)
        XCTAssertEqual(strategy.currentWatermark, 0)
    }

    func testWatermarkWithoutElementCountsBackPressureStrategy() async throws {
        typealias Strategy = AsyncBackpressuredStream<[String], any Error>.HighLowWatermarkBackPressureStrategy
        var strategy = Strategy(lowWatermark: 2, highWatermark: 3)

        XCTAssertEqual(strategy.currentWatermark, 0)
        XCTAssertEqual(strategy.didYield(elements: Slice([])), true)
        XCTAssertEqual(strategy.currentWatermark, 0)
        XCTAssertEqual(strategy.didYield(elements: Slice([["*", "*"]])), true)
        XCTAssertEqual(strategy.currentWatermark, 1)
        XCTAssertEqual(strategy.didYield(elements: Slice([["*", "*"]])), true)
        XCTAssertEqual(strategy.currentWatermark, 2)

        XCTAssertEqual(strategy.currentWatermark, 2)
        XCTAssertEqual(strategy.didConsume(elements: Slice([])), false)
        XCTAssertEqual(strategy.currentWatermark, 2)
        XCTAssertEqual(strategy.didConsume(elements: Slice([["*", "*"]])), true)
        XCTAssertEqual(strategy.currentWatermark, 1)
        XCTAssertEqual(strategy.didConsume(elements: Slice([["*", "*"]])), true)
        XCTAssertEqual(strategy.currentWatermark, 0)
        XCTAssertEqual(strategy.didConsume(elements: Slice([])), true)
        XCTAssertEqual(strategy.currentWatermark, 0)
    }

    func testWatermarkWithElementCountsBackPressureStrategy() async throws {
        typealias Strategy = AsyncBackpressuredStream<[String], any Error>.HighLowWatermarkBackPressureStrategy
        var strategy = Strategy(lowWatermark: 2, highWatermark: 3, waterLevelForElement: { $0.count })
        XCTAssertEqual(strategy.currentWatermark, 0)
        XCTAssertEqual(strategy.didYield(elements: Slice([])), true)
        XCTAssertEqual(strategy.currentWatermark, 0)
        XCTAssertEqual(strategy.didYield(elements: Slice([["*", "*"]])), true)
        XCTAssertEqual(strategy.currentWatermark, 2)
        XCTAssertEqual(strategy.didYield(elements: Slice([["*", "*"]])), false)
        XCTAssertEqual(strategy.currentWatermark, 4)

        XCTAssertEqual(strategy.currentWatermark, 4)
        XCTAssertEqual(strategy.didConsume(elements: Slice([])), false)
        XCTAssertEqual(strategy.currentWatermark, 4)
        XCTAssertEqual(strategy.didConsume(elements: Slice([["*", "*"]])), false)
        XCTAssertEqual(strategy.currentWatermark, 2)
        XCTAssertEqual(strategy.didConsume(elements: Slice([["*", "*"]])), true)
        XCTAssertEqual(strategy.currentWatermark, 0)
        XCTAssertEqual(strategy.didConsume(elements: Slice([])), true)
        XCTAssertEqual(strategy.currentWatermark, 0)
    }
}

extension AsyncSequence {
    /// Collect all elements in the sequence into an array.
    fileprivate func collect() async rethrows -> [Element] {
        try await self.reduce(into: []) { accumulated, next in accumulated.append(next) }
    }
}
