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

    func testWritingOverWatermark() async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            let (stream, continuation) = AsyncBackpressuredStream<Int, any Error>
                .makeStream(backPressureStrategy: .highLowWatermark(lowWatermark: 1, highWatermark: 1))

            group.addTask {
                for i in 1...10 {
                    debug("Producer writing element \(i)...")
                    let writeResult = try continuation.write(contentsOf: CollectionOfOne(i))
                    debug("Producer wrote element \(i), result = \(writeResult)")
                    // ignore backpressure result and write again anyway
                }
                debug("Producer finished")
                continuation.finish(throwing: nil)
            }

            var iterator = stream.makeAsyncIterator()
            var numElementsConsumed = 0
            var expectedNextValue = 1
            while true {
                debug("Consumer reading element...")
                guard let element = try await iterator.next() else { break }
                XCTAssertEqual(element, expectedNextValue)
                debug("Consumer read element: \(element), expected: \(expectedNextValue)")
                numElementsConsumed += 1
                expectedNextValue += 1
            }
            XCTAssertEqual(numElementsConsumed, 10)

            group.cancelAll()
        }
    }

    func testStateMachineSuspendNext() async throws {
        typealias Stream = AsyncBackpressuredStream<Int, any Error>

        var strategy = Stream.InternalBackPressureStrategy.highLowWatermark(.init(lowWatermark: 1, highWatermark: 1))
        _ = strategy.didYield(elements: Slice([1, 2, 3]))
        var stateMachine = Stream.StateMachine(backPressureStrategy: strategy, onTerminate: nil)
        stateMachine.state = .streaming(
            backPressureStrategy: strategy,
            buffer: [1, 2, 3],
            consumerContinuation: nil,
            producerContinuations: [],
            cancelledAsyncProducers: [],
            hasOutstandingDemand: false,
            iteratorInitialized: true,
            onTerminate: nil
        )

        guard case .streaming(_, let buffer, let consumerContinuation, _, _, _, _, _) = stateMachine.state else {
            XCTFail("Unexpected state: \(stateMachine.state)")
            return
        }
        XCTAssertEqual(buffer, [1, 2, 3])
        XCTAssertNil(consumerContinuation)

        _ = try await withCheckedThrowingContinuation { continuation in
            let action = stateMachine.suspendNext(continuation: continuation)

            guard case .resumeContinuationWithElement(_, let element) = action else {
                XCTFail("Unexpected action: \(action)")
                return
            }
            XCTAssertEqual(element, 1)

            guard case .streaming(_, let buffer, let consumerContinuation, _, _, _, _, _) = stateMachine.state else {
                XCTFail("Unexpected state: \(stateMachine.state)")
                return
            }
            XCTAssertEqual(buffer, [2, 3])
            XCTAssertNil(consumerContinuation)

            continuation.resume(returning: element)
        }
    }
}

extension AsyncBackpressuredStream.Source.WriteResult: CustomStringConvertible {
    // swift-format-ignore: AllPublicDeclarationsHaveDocumentation
    public var description: String {
        switch self {
        case .enqueueCallback: return "enqueueCallBack"
        case .produceMore: return "produceMore"
        }
    }
}

extension AsyncBackpressuredStream.StateMachine.SuspendNextAction: CustomStringConvertible {
    // swift-format-ignore: AllPublicDeclarationsHaveDocumentation
    public var description: String {
        switch self {
        case .none: return "none"
        case .resumeContinuationWithElement: return "resumeContinuationWithElement"
        case .resumeContinuationWithElementAndProducers: return "resumeContinuationWithElementAndProducers"
        case .resumeContinuationWithFailureAndCallOnTerminate: return "resumeContinuationWithFailureAndCallOnTerminate"
        case .resumeContinuationWithNil: return "resumeContinuationWithNil"
        }
    }
}

extension AsyncBackpressuredStream.StateMachine.State: CustomStringConvertible {
    // swift-format-ignore: AllPublicDeclarationsHaveDocumentation
    public var description: String {
        switch self {
        case .initial: return "initial"
        case .streaming(_, let buffer, let consumer, let producers, _, let demand, _, _):
            return
                "streaming(buffer.count: \(buffer.count), consumer: \(consumer != nil ? "yes" : "no"), producers: \(producers), demand: \(demand))"
        case .finished: return "finished"
        case .sourceFinished: return "sourceFinished"
        }
    }
}

extension AsyncSequence {
    /// Collect all elements in the sequence into an array.
    fileprivate func collect() async rethrows -> [Element] {
        try await self.reduce(into: []) { accumulated, next in accumulated.append(next) }
    }
}

extension AsyncBackpressuredStream.StateMachine.NextAction: CustomStringConvertible {
    // swift-format-ignore: AllPublicDeclarationsHaveDocumentation
    public var description: String {
        switch self {
        case .returnNil: return "returnNil"
        case .returnElementAndResumeProducers: return "returnElementAndResumeProducers"
        case .returnFailureAndCallOnTerminate: return "returnFailureAndCallOnTerminate"
        case .returnElement: return "returnElement"
        case .suspendTask: return "suspendTask"
        }
    }
}

extension AsyncBackpressuredStream.StateMachine.WriteAction: CustomStringConvertible {
    // swift-format-ignore: AllPublicDeclarationsHaveDocumentation
    public var description: String {
        switch self {
        case .returnProduceMore: return "returnProduceMore"
        case .returnEnqueue: return "returnEnqueue"
        case .resumeConsumerContinuationAndReturnProduceMore: return "resumeConsumerContinuationAndReturnProduceMore"
        case .resumeConsumerContinuationAndReturnEnqueue: return "resumeConsumerContinuationAndReturnEnqueue"
        case .throwFinishedError: return "throwFinishedError"
        }
    }
}

extension AsyncBackpressuredStream.StateMachine.EnqueueProducerAction: CustomStringConvertible {
    // swift-format-ignore: AllPublicDeclarationsHaveDocumentation
    public var description: String {
        switch self {
        case .resumeProducer: return "resumeProducer"
        case .resumeProducerWithCancellationError: return "resumeProducerWithCancellationError"
        case .none: return "none"
        }
    }
}
