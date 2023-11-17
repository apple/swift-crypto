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
// swift-format-ignore-file
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
import DequeModule

struct AsyncBackpressuredStream<Element: Sendable, Failure: Error>: Sendable {
    /// A mechanism to interface between producer code and an asynchronous stream.
    ///
    /// Use this source to provide elements to the stream by calling one of the `write` methods, then terminate the stream normally
    /// by calling the `finish()` method. You can also use the source's `finish(throwing:)` method to terminate the stream by
    /// throwing an error.
    struct Source: Sendable {
        /// A strategy that handles the back pressure of the asynchronous stream.
        struct BackPressureStrategy: Sendable {
            var internalBackPressureStrategy: InternalBackPressureStrategy

            /// When the high water mark is reached producers will be suspended. All producers will be resumed again once
            /// the low water mark is reached.
            static func highLowWatermark(lowWatermark: Int, highWatermark: Int) -> BackPressureStrategy {
                .init(
                    internalBackPressureStrategy: .highLowWatermark(
                        .init(lowWatermark: lowWatermark, highWatermark: highWatermark)
                    )
                )
            }

            /// When the high water mark is reached producers will be suspended. All producers will be resumed again once
            /// the low water mark is reached. When `usingElementCounts` is true, the counts of the element types will
            /// be used to compute the watermark.
            static func highLowWatermarkWithElementCounts(lowWatermark: Int, highWatermark: Int)
                -> BackPressureStrategy where Element: RandomAccessCollection
            {
                .init(
                    internalBackPressureStrategy: .highLowWatermark(
                        .init(
                            lowWatermark: lowWatermark,
                            highWatermark: highWatermark,
                            waterLevelForElement: { $0.count }
                        )
                    )
                )
            }
        }

        /// A type that indicates the result of writing elements to the source.
        enum WriteResult: Sendable {
            /// A token that is returned when the asynchronous stream's back pressure strategy indicated that any producer should
            /// be suspended. Use this token to enqueue a callback by  calling the ``enqueueCallback(_:)`` method.
            struct WriteToken: Sendable {
                let id: UInt

                init(id: UInt) { self.id = id }
            }
            /// Indicates that more elements should be produced and written to the source.
            case produceMore
            /// Indicates that a callback should be enqueued.
            ///
            /// The associated token should be passed to the ``enqueueCallback(_:)`` method.
            case enqueueCallback(WriteToken)
        }

        private var storage: Storage

        init(storage: Storage) { self.storage = storage }

        /// Write new elements to the asynchronous stream.
        ///
        /// If there is a task consuming the stream and awaiting the next element then the task will get resumed with the
        /// first element of the provided sequence. If the asynchronous stream already terminated then this method will throw an error
        /// indicating the failure.
        ///
        /// - Parameter sequence: The elements to write to the asynchronous stream.
        /// - Returns: The result that indicates if more elements should be produced at this time.
        func write<S: Sequence>(contentsOf sequence: S) throws -> WriteResult where S.Element == Element {
            try self.storage.write(contentsOf: sequence)
        }

        /// Enqueues a callback that will be invoked once more elements should be produced.
        ///
        /// Call this method after ``write(contentsOf:)`` returned a ``WriteResult/enqueueCallback(_:)``.
        ///
        /// - Parameters:
        ///   - writeToken: The write token produced by ``write(contentsOf:)``.
        ///   - onProduceMore: The callback which gets invoked once more elements should be produced.
        func enqueueCallback(
            writeToken: WriteResult.WriteToken,
            onProduceMore: @escaping @Sendable (Result<Void, any Error>) -> Void
        ) { self.storage.enqueueProducer(writeToken: writeToken, onProduceMore: onProduceMore) }

        /// Cancel an enqueued callback.
        ///
        /// Call this method to cancel a callback enqueued by the ``enqueueCallback(writeToken:onProduceMore:)`` method.
        ///
        /// > Note: This methods supports being called before ``enqueueCallback(writeToken:onProduceMore:)`` is called and
        /// will mark the passed `writeToken` as cancelled.
        /// - Parameter writeToken: The write token produced by ``write(contentsOf:)``.
        func cancelCallback(writeToken: WriteResult.WriteToken) {
            self.storage.cancelProducer(writeToken: writeToken)
        }

        /// Write new elements to the asynchronous stream and provide a callback which will be invoked once more elements should be produced.
        ///
        /// - Parameters:
        ///   - sequence: The elements to write to the asynchronous stream.
        ///   - onProduceMore: The callback which gets invoked once more elements should be produced. This callback might be
        ///   invoked during the call to ``write(contentsOf:onProduceMore:)``.
        func write<S: Sequence>(
            contentsOf sequence: S,
            onProduceMore: @escaping @Sendable (Result<Void, any Error>) -> Void
        ) where S.Element == Element {
            do {
                let writeResult = try self.write(contentsOf: sequence)

                switch writeResult {
                case .produceMore: onProduceMore(.success(()))

                case .enqueueCallback(let writeToken):
                    self.enqueueCallback(writeToken: writeToken, onProduceMore: onProduceMore)
                }
            } catch { onProduceMore(.failure(error)) }
        }

        /// Write new elements to the asynchronous stream.
        ///
        /// This method returns once more elements should be produced.
        ///
        /// - Parameters:
        ///   - sequence: The elements to write to the asynchronous stream.
        func asyncWrite<S: Sequence>(contentsOf sequence: S) async throws where S.Element == Element {
            let writeResult = try self.write(contentsOf: sequence)

            switch writeResult {
            case .produceMore: return

            case .enqueueCallback(let writeToken):
                try await withTaskCancellationHandler {
                    try await withCheckedThrowingContinuation { continuation in
                        self.enqueueCallback(
                            writeToken: writeToken,
                            onProduceMore: { result in
                                switch result {
                                case .success(): continuation.resume(returning: ())
                                case .failure(let error): continuation.resume(throwing: error)
                                }
                            }
                        )
                    }
                } onCancel: {
                    self.cancelCallback(writeToken: writeToken)
                }

            }
        }

        func finish(throwing failure: Failure?) { self.storage.finish(failure) }
    }

    private var storage: Storage

    init(storage: Storage) { self.storage = storage }

    static func makeStream(
        of elementType: Element.Type = Element.self,
        backPressureStrategy: Source.BackPressureStrategy,
        onTermination: (@Sendable () -> Void)? = nil
    ) -> (Self, Source) where Failure == any Error {
        let storage = Storage(
            backPressureStrategy: backPressureStrategy.internalBackPressureStrategy,
            onTerminate: onTermination
        )
        let source = Source(storage: storage)

        return (.init(storage: storage), source)
    }
}

extension AsyncBackpressuredStream: AsyncSequence {
    struct AsyncIterator: AsyncIteratorProtocol {
        private var storage: Storage

        init(storage: Storage) { self.storage = storage }

        mutating func next() async throws -> Element? { return try await storage.next() }
    }

    func makeAsyncIterator() -> AsyncIterator { return AsyncIterator(storage: self.storage) }
}

extension AsyncBackpressuredStream {
    struct HighLowWatermarkBackPressureStrategy {
        private let lowWatermark: Int
        private let highWatermark: Int
        private(set) var currentWatermark: Int

        typealias CustomWaterLevelForElement = @Sendable (Element) -> Int
        private let waterLevelForElement: CustomWaterLevelForElement?

        /// Initializes a new ``HighLowWatermarkBackPressureStrategy``.
        ///
        /// - Parameters:
        ///   - lowWatermark: The low watermark where demand should start.
        ///   - highWatermark: The high watermark where demand should be stopped.
        init(lowWatermark: Int, highWatermark: Int, waterLevelForElement: CustomWaterLevelForElement? = nil) {
            precondition(lowWatermark <= highWatermark, "Low watermark must be <= high watermark")
            self.lowWatermark = lowWatermark
            self.highWatermark = highWatermark
            self.currentWatermark = 0
            self.waterLevelForElement = waterLevelForElement
        }

        mutating func didYield(elements: Deque<Element>.SubSequence) -> Bool {
            if let waterLevelForElement {
                self.currentWatermark += elements.reduce(0) { $0 + waterLevelForElement($1) }
            } else {
                self.currentWatermark += elements.count
            }
            precondition(self.currentWatermark >= 0, "Watermark below zero")
            // We are demanding more until we reach the high watermark
            return self.currentWatermark < self.highWatermark
        }

        mutating func didConsume(elements: Deque<Element>.SubSequence) -> Bool {
            if let waterLevelForElement {
                self.currentWatermark -= elements.reduce(0) { $0 + waterLevelForElement($1) }
            } else {
                self.currentWatermark -= elements.count
            }
            precondition(self.currentWatermark >= 0, "Watermark below zero")
            // We start demanding again once we are below the low watermark
            return self.currentWatermark < self.lowWatermark
        }

        mutating func didConsume(element: Element) -> Bool {
            if let waterLevelForElement {
                self.currentWatermark -= waterLevelForElement(element)
            } else {
                self.currentWatermark -= 1
            }
            precondition(self.currentWatermark >= 0, "Watermark below zero")
            // We start demanding again once we are below the low watermark
            return self.currentWatermark < self.lowWatermark
        }
    }

    enum InternalBackPressureStrategy {
        case highLowWatermark(HighLowWatermarkBackPressureStrategy)

        mutating func didYield(elements: Deque<Element>.SubSequence) -> Bool {
            switch self {
            case .highLowWatermark(var strategy):
                let result = strategy.didYield(elements: elements)
                self = .highLowWatermark(strategy)
                return result
            }
        }

        mutating func didConsume(elements: Deque<Element>.SubSequence) -> Bool {
            switch self {
            case .highLowWatermark(var strategy):
                let result = strategy.didConsume(elements: elements)
                self = .highLowWatermark(strategy)
                return result
            }
        }

        mutating func didConsume(element: Element) -> Bool {
            switch self {
            case .highLowWatermark(var strategy):
                let result = strategy.didConsume(element: element)
                self = .highLowWatermark(strategy)
                return result
            }
        }
    }
}

extension AsyncBackpressuredStream {
    final class Storage: @unchecked Sendable {
        /// The lock that protects the state machine and the nextProducerID.
        let lock = NIOLock()

        /// The state machine.
        var stateMachine: StateMachine

        /// The next producer's id.
        var nextProducerID: UInt = 0

        init(backPressureStrategy: InternalBackPressureStrategy, onTerminate: (() -> Void)?) {
            self.stateMachine = .init(backPressureStrategy: backPressureStrategy, onTerminate: onTerminate)
        }

        func sequenceDeinitialized() {
            let onTerminate = self.lock.withLock {
                let action = self.stateMachine.sequenceDeinitialized()

                switch action {
                case .callOnTerminate(let onTerminate):
                    // We have to call onTerminate without the lock to avoid potential deadlocks
                    return onTerminate

                case .none: return nil
                }
            }

            onTerminate?()
        }

        func iteratorInitialized() { self.lock.withLock { self.stateMachine.iteratorInitialized() } }

        func iteratorDeinitialized() {
            let onTerminate = self.lock.withLock {
                let action = self.stateMachine.iteratorDeinitialized()

                switch action {
                case .callOnTerminate(let onTerminate):
                    // We have to call onTerminate without the lock to avoid potential deadlocks
                    return onTerminate

                case .none: return nil
                }
            }

            onTerminate?()
        }

        func write<S: Sequence>(contentsOf sequence: S) throws -> Source.WriteResult where S.Element == Element {
            let action = self.lock.withLock { return self.stateMachine.write(sequence) }

            switch action {
            case .returnProduceMore: return .produceMore

            case .returnEnqueue:
                // TODO: Move the id into the state machine or use an atomic
                let id = self.lock.withLock {
                    let id = self.nextProducerID
                    self.nextProducerID += 1
                    return id
                }
                return .enqueueCallback(.init(id: id))

            case .resumeConsumerContinuationAndReturnProduceMore(let continuation, let element):
                continuation.resume(returning: element)
                return .produceMore

            case .resumeConsumerContinuationAndReturnEnqueue(let continuation, let element):
                continuation.resume(returning: element)
                // TODO: Move the id into the state machine or use an atomic
                let id = self.lock.withLock {
                    let id = self.nextProducerID
                    self.nextProducerID += 1
                    return id
                }
                return .enqueueCallback(.init(id: id))

            case .throwFinishedError:
                // TODO: Introduce new Error
                throw CancellationError()
            }
        }

        func enqueueProducer(
            writeToken: Source.WriteResult.WriteToken,
            onProduceMore: @escaping @Sendable (Result<Void, any Error>) -> Void
        ) {
            let action = self.lock.withLock {
                return self.stateMachine.enqueueProducer(writeToken: writeToken, onProduceMore: onProduceMore)
            }

            switch action {
            case .resumeProducer(let onProduceMore): onProduceMore(.success(()))

            case .resumeProducerWithCancellationError(let onProduceMore): onProduceMore(.failure(CancellationError()))

            case .none: break
            }
        }

        func cancelProducer(writeToken: Source.WriteResult.WriteToken) {
            let action = self.lock.withLock { return self.stateMachine.cancelProducer(writeToken: writeToken) }

            switch action {
            case .resumeProducerWithCancellationError(let onProduceMore): onProduceMore(.failure(CancellationError()))

            case .none: break
            }
        }

        func finish(_ failure: Failure?) {
            let onTerminate = self.lock.withLock {
                let action = self.stateMachine.finish(failure)

                switch action {
                case .resumeAllContinuationsAndCallOnTerminate(
                    let consumerContinuation,
                    let failure,
                    let producerContinuations,
                    let onTerminate
                ):
                    // It is safe to resume the continuation while holding the lock
                    // since the task will get enqueued on its executor and the resume method
                    // is returning immediately
                    switch failure {
                    case .some(let error): consumerContinuation.resume(throwing: error)
                    case .none: consumerContinuation.resume(returning: nil)
                    }

                    for producerContinuation in producerContinuations {
                        // TODO: Throw a new cancelled error
                        producerContinuation(.failure(CancellationError()))
                    }

                    return onTerminate

                case .resumeProducerContinuations(let producerContinuations):
                    for producerContinuation in producerContinuations {
                        // TODO: Throw a new cancelled error
                        producerContinuation(.failure(CancellationError()))
                    }

                    return nil

                case .none: return nil
                }
            }

            onTerminate?()
        }

        func next() async throws -> Element? {
            let action = self.lock.withLock { return self.stateMachine.next() }

            switch action {
            case .returnElement(let element): return element

            case .returnElementAndResumeProducers(let element, let producerContinuations):
                for producerContinuation in producerContinuations { producerContinuation(.success(())) }

                return element

            case .returnFailureAndCallOnTerminate(let failure, let onTerminate):
                onTerminate?()
                switch failure {
                case .some(let error): throw error

                case .none: return nil
                }

            case .returnNil: return nil

            case .suspendTask: return try await suspendNext()
            }
        }

        func suspendNext() async throws -> Element? {
            return try await withTaskCancellationHandler {
                return try await withCheckedThrowingContinuation { continuation in
                    let action = self.lock.withLock { return self.stateMachine.suspendNext(continuation: continuation) }

                    switch action {
                    case .resumeContinuationWithElement(let continuation, let element):
                        continuation.resume(returning: element)

                    case .resumeContinuationWithElementAndProducers(
                        let continuation,
                        let element,
                        let producerContinuations
                    ):
                        continuation.resume(returning: element)
                        for producerContinuation in producerContinuations { producerContinuation(.success(())) }

                    case .resumeContinuationWithFailureAndCallOnTerminate(
                        let continuation,
                        let failure,
                        let onTerminate
                    ):
                        onTerminate?()
                        switch failure {
                        case .some(let error): continuation.resume(throwing: error)

                        case .none: continuation.resume(returning: nil)
                        }

                    case .resumeContinuationWithNil(let continuation): continuation.resume(returning: nil)

                    case .none: break
                    }
                }
            } onCancel: {
                self.lock.withLockVoid {
                    let action = self.stateMachine.cancelNext()

                    switch action {
                    case .resumeContinuationWithCancellationErrorAndFinishProducersAndCallOnTerminate(
                        let continuation,
                        let producerContinuations,
                        let onTerminate
                    ):
                        onTerminate?()
                        continuation.resume(throwing: CancellationError())
                        for producerContinuation in producerContinuations {
                            // TODO: Throw a new cancelled error
                            producerContinuation(.failure(CancellationError()))
                        }

                    case .finishProducersAndCallOnTerminate(let producerContinuations, let onTerminate):
                        onTerminate?()
                        for producerContinuation in producerContinuations {
                            // TODO: Throw a new cancelled error
                            producerContinuation(.failure(CancellationError()))
                        }

                    case .none: break
                    }
                }
            }
        }
    }
}

extension AsyncBackpressuredStream {
    struct StateMachine {
        enum State {
            case initial(
                backPressureStrategy: InternalBackPressureStrategy,
                iteratorInitialized: Bool,
                onTerminate: (() -> Void)?
            )

            /// The state once either any element was yielded or `next()` was called.
            case streaming(
                backPressureStrategy: InternalBackPressureStrategy,
                buffer: Deque<Element>,
                consumerContinuation: CheckedContinuation<Element?, any Error>?,
                producerContinuations: Deque<(UInt, (Result<Void, any Error>) -> Void)>,
                cancelledAsyncProducers: Deque<UInt>,
                hasOutstandingDemand: Bool,
                iteratorInitialized: Bool,
                onTerminate: (() -> Void)?
            )

            /// The state once the underlying source signalled that it is finished.
            case sourceFinished(
                buffer: Deque<Element>,
                iteratorInitialized: Bool,
                failure: Failure?,
                onTerminate: (() -> Void)?
            )

            /// The state once there can be no outstanding demand. This can happen if:
            /// 1. The iterator was deinited
            /// 2. The underlying source finished and all buffered elements have been consumed
            case finished(iteratorInitialized: Bool)
        }

        /// The state machine's current state.
        var state: State

        var producerContinuationCounter: UInt = 0

        /// Initializes a new `StateMachine`.
        ///
        /// We are passing and holding the back-pressure strategy here because
        /// it is a customizable extension of the state machine.
        ///
        /// - Parameter backPressureStrategy: The back-pressure strategy.
        init(backPressureStrategy: InternalBackPressureStrategy, onTerminate: (() -> Void)?) {
            self.state = .initial(
                backPressureStrategy: backPressureStrategy,
                iteratorInitialized: false,
                onTerminate: onTerminate
            )
        }

        /// Actions returned by `sequenceDeinitialized()`.
        enum SequenceDeinitializedAction {
            /// Indicates that `onTerminate` should be called.
            case callOnTerminate((() -> Void)?)
            /// Indicates that nothing should be done.
            case none
        }

        mutating func sequenceDeinitialized() -> SequenceDeinitializedAction {
            switch self.state {
            case .initial(_, iteratorInitialized: false, let onTerminate),
                .streaming(_, _, _, _, _, _, iteratorInitialized: false, let onTerminate),
                .sourceFinished(_, iteratorInitialized: false, _, let onTerminate):
                // No iterator was created so we can transition to finished right away.
                self.state = .finished(iteratorInitialized: false)

                return .callOnTerminate(onTerminate)

            case .initial(_, iteratorInitialized: true, _), .streaming(_, _, _, _, _, _, iteratorInitialized: true, _),
                .sourceFinished(_, iteratorInitialized: true, _, _):
                // An iterator was created and we deinited the sequence.
                // This is an expected pattern and we just continue on normal.
                return .none

            case .finished:
                // We are already finished so there is nothing left to clean up.
                // This is just the references dropping afterwards.
                return .none
            }
        }

        mutating func iteratorInitialized() {
            switch self.state {
            case .initial(_, iteratorInitialized: true, _), .streaming(_, _, _, _, _, _, iteratorInitialized: true, _),
                .sourceFinished(_, iteratorInitialized: true, _, _), .finished(iteratorInitialized: true):
                // Our sequence is a unicast sequence and does not support multiple AsyncIterator's
                fatalError("Only a single AsyncIterator can be created")

            case .initial(let backPressureStrategy, iteratorInitialized: false, let onTerminate):
                // The first and only iterator was initialized.
                self.state = .initial(
                    backPressureStrategy: backPressureStrategy,
                    iteratorInitialized: true,
                    onTerminate: onTerminate
                )

            case .streaming(
                let backPressureStrategy,
                let buffer,
                let consumerContinuation,
                let producerContinuations,
                let cancelledAsyncProducers,
                let hasOutstandingDemand,
                false,
                let onTerminate
            ):
                // The first and only iterator was initialized.
                self.state = .streaming(
                    backPressureStrategy: backPressureStrategy,
                    buffer: buffer,
                    consumerContinuation: consumerContinuation,
                    producerContinuations: producerContinuations,
                    cancelledAsyncProducers: cancelledAsyncProducers,
                    hasOutstandingDemand: hasOutstandingDemand,
                    iteratorInitialized: true,
                    onTerminate: onTerminate
                )

            case .sourceFinished(let buffer, false, let failure, let onTerminate):
                // The first and only iterator was initialized.
                self.state = .sourceFinished(
                    buffer: buffer,
                    iteratorInitialized: true,
                    failure: failure,
                    onTerminate: onTerminate
                )

            case .finished(iteratorInitialized: false):
                // It is strange that an iterator is created after we are finished
                // but it can definitely happen, e.g.
                // Sequence.init -> source.finish -> sequence.makeAsyncIterator
                self.state = .finished(iteratorInitialized: true)
            }
        }

        /// Actions returned by `iteratorDeinitialized()`.
        enum IteratorDeinitializedAction {
            /// Indicates that `onTerminate` should be called.
            case callOnTerminate((() -> Void)?)
            /// Indicates that nothing should be done.
            case none
        }

        mutating func iteratorDeinitialized() -> IteratorDeinitializedAction {
            switch self.state {
            case .initial(_, iteratorInitialized: false, _),
                .streaming(_, _, _, _, _, _, iteratorInitialized: false, _),
                .sourceFinished(_, iteratorInitialized: false, _, _):
                // An iterator needs to be initialized before it can be deinitialized.
                preconditionFailure("Internal inconsistency")

            case .initial(_, iteratorInitialized: true, let onTerminate),
                .streaming(_, _, _, _, _, _, iteratorInitialized: true, let onTerminate),
                .sourceFinished(_, iteratorInitialized: true, _, let onTerminate):
                // An iterator was created and deinited. Since we only support
                // a single iterator we can now transition to finish and inform the delegate.
                self.state = .finished(iteratorInitialized: true)

                return .callOnTerminate(onTerminate)

            case .finished:
                // We are already finished so there is nothing left to clean up.
                // This is just the references dropping afterwards.
                return .none
            }
        }

        /// Actions returned by `yield()`.
        enum WriteAction {
            /// Indicates that the producer should be notified to produce more.
            case returnProduceMore
            /// Indicates that the producer should be suspended to stop producing.
            case returnEnqueue
            /// Indicates that the consumer continuation should be resumed and the producer should be notified to produce more.
            case resumeConsumerContinuationAndReturnProduceMore(
                continuation: CheckedContinuation<Element?, any Error>,
                element: Element
            )
            /// Indicates that the consumer continuation should be resumed and the producer should be suspended.
            case resumeConsumerContinuationAndReturnEnqueue(
                continuation: CheckedContinuation<Element?, any Error>,
                element: Element
            )
            /// Indicates that the producer has been finished.
            case throwFinishedError

            init(
                shouldProduceMore: Bool,
                continuationAndElement: (CheckedContinuation<Element?, any Error>, Element)? = nil
            ) {
                switch (shouldProduceMore, continuationAndElement) {
                case (true, .none): self = .returnProduceMore

                case (false, .none): self = .returnEnqueue

                case (true, .some((let continuation, let element))):
                    self = .resumeConsumerContinuationAndReturnProduceMore(continuation: continuation, element: element)

                case (false, .some((let continuation, let element))):
                    self = .resumeConsumerContinuationAndReturnEnqueue(continuation: continuation, element: element)
                }
            }
        }

        mutating func write<S: Sequence>(_ sequence: S) -> WriteAction where S.Element == Element {
            switch self.state {
            case .initial(var backPressureStrategy, let iteratorInitialized, let onTerminate):
                let buffer = Deque<Element>(sequence)
                let shouldProduceMore = backPressureStrategy.didYield(elements: buffer[...])

                self.state = .streaming(
                    backPressureStrategy: backPressureStrategy,
                    buffer: buffer,
                    consumerContinuation: nil,
                    producerContinuations: .init(),
                    cancelledAsyncProducers: .init(),
                    hasOutstandingDemand: shouldProduceMore,
                    iteratorInitialized: iteratorInitialized,
                    onTerminate: onTerminate
                )

                return .init(shouldProduceMore: shouldProduceMore)

            case .streaming(
                var backPressureStrategy,
                var buffer,
                .some(let consumerContinuation),
                let producerContinuations,
                let cancelledAsyncProducers,
                let hasOutstandingDemand,
                let iteratorInitialized,
                let onTerminate
            ):
                // The buffer should always be empty if we hold a continuation
                precondition(buffer.isEmpty, "Expected an empty buffer")

                let bufferEndIndexBeforeAppend = buffer.endIndex
                buffer.append(contentsOf: sequence)
                _ = backPressureStrategy.didYield(elements: buffer[bufferEndIndexBeforeAppend...])

                guard let element = buffer.popFirst() else {
                    // We got a yield of an empty sequence. We just tolerate this.
                    self.state = .streaming(
                        backPressureStrategy: backPressureStrategy,
                        buffer: buffer,
                        consumerContinuation: consumerContinuation,
                        producerContinuations: producerContinuations,
                        cancelledAsyncProducers: cancelledAsyncProducers,
                        hasOutstandingDemand: hasOutstandingDemand,
                        iteratorInitialized: iteratorInitialized,
                        onTerminate: onTerminate
                    )
                    return .init(shouldProduceMore: hasOutstandingDemand)
                }

                // We have an element and can resume the continuation

                let shouldProduceMore = backPressureStrategy.didConsume(element: element)
                self.state = .streaming(
                    backPressureStrategy: backPressureStrategy,
                    buffer: buffer,
                    consumerContinuation: nil,  // Setting this to nil since we are resuming the continuation
                    producerContinuations: producerContinuations,
                    cancelledAsyncProducers: cancelledAsyncProducers,
                    hasOutstandingDemand: shouldProduceMore,
                    iteratorInitialized: iteratorInitialized,
                    onTerminate: onTerminate
                )

                return .init(
                    shouldProduceMore: shouldProduceMore,
                    continuationAndElement: (consumerContinuation, element)
                )

            case .streaming(
                var backPressureStrategy,
                var buffer,
                consumerContinuation: .none,
                let producerContinuations,
                let cancelledAsyncProducers,
                _,
                let iteratorInitialized,
                let onTerminate
            ):
                let bufferEndIndexBeforeAppend = buffer.endIndex
                buffer.append(contentsOf: sequence)
                let shouldProduceMore = backPressureStrategy.didYield(elements: buffer[bufferEndIndexBeforeAppend...])

                self.state = .streaming(
                    backPressureStrategy: backPressureStrategy,
                    buffer: buffer,
                    consumerContinuation: nil,
                    producerContinuations: producerContinuations,
                    cancelledAsyncProducers: cancelledAsyncProducers,
                    hasOutstandingDemand: shouldProduceMore,
                    iteratorInitialized: iteratorInitialized,
                    onTerminate: onTerminate
                )

                return .init(shouldProduceMore: shouldProduceMore)

            case .sourceFinished, .finished:
                // If the source has finished we are dropping the elements.
                return .throwFinishedError
            }
        }

        /// Actions returned by `suspendYield()`.
        @usableFromInline enum EnqueueProducerAction {
            case resumeProducer((Result<Void, any Error>) -> Void)
            case resumeProducerWithCancellationError((Result<Void, any Error>) -> Void)
            case none
        }

        @inlinable mutating func enqueueProducer(
            writeToken: Source.WriteResult.WriteToken,
            onProduceMore: @escaping (Result<Void, any Error>) -> Void
        ) -> EnqueueProducerAction {
            switch self.state {
            case .initial:
                // We need to transition to streaming before we can suspend
                preconditionFailure("Internal inconsistency")

            case .streaming(
                let backPressureStrategy,
                let buffer,
                let consumerContinuation,
                var producerContinuations,
                var cancelledAsyncProducers,
                let hasOutstandingDemand,
                let iteratorInitialized,
                let onTerminate
            ):
                if let index = cancelledAsyncProducers.firstIndex(of: writeToken.id) {
                    cancelledAsyncProducers.remove(at: index)
                    self.state = .streaming(
                        backPressureStrategy: backPressureStrategy,
                        buffer: buffer,
                        consumerContinuation: consumerContinuation,
                        producerContinuations: producerContinuations,
                        cancelledAsyncProducers: cancelledAsyncProducers,
                        hasOutstandingDemand: hasOutstandingDemand,
                        iteratorInitialized: iteratorInitialized,
                        onTerminate: onTerminate
                    )

                    return .resumeProducerWithCancellationError(onProduceMore)
                } else if hasOutstandingDemand {
                    // We hit an edge case here where we yielded but got suspended afterwards
                    // and in-between yielding and suspending the yield we got consumption which lead us
                    // to produce more again.
                    return .resumeProducer(onProduceMore)
                } else {
                    producerContinuations.append((writeToken.id, onProduceMore))

                    self.state = .streaming(
                        backPressureStrategy: backPressureStrategy,
                        buffer: buffer,
                        consumerContinuation: consumerContinuation,
                        producerContinuations: producerContinuations,
                        cancelledAsyncProducers: cancelledAsyncProducers,
                        hasOutstandingDemand: hasOutstandingDemand,
                        iteratorInitialized: iteratorInitialized,
                        onTerminate: onTerminate
                    )

                    return .none
                }

            case .sourceFinished, .finished:
                // Since we are unlocking between yielding and suspending the yield
                // It can happen that the source got finished or the consumption fully finishes.
                return .none
            }
        }

        /// Actions returned by `cancelYield()`.
        enum CancelYieldAction {
            case resumeProducerWithCancellationError((Result<Void, any Error>) -> Void)
            case none
        }

        mutating func cancelProducer(writeToken: Source.WriteResult.WriteToken) -> CancelYieldAction {
            switch self.state {
            case .initial:
                // We need to transition to streaming before we can suspend
                preconditionFailure("Internal inconsistency")

            case .streaming(
                let backPressureStrategy,
                let buffer,
                let consumerContinuation,
                var producerContinuations,
                var cancelledAsyncProducers,
                let hasOutstandingDemand,
                let iteratorInitialized,
                let onTerminate
            ):
                guard let index = producerContinuations.firstIndex(where: { $0.0 == writeToken.id }) else {
                    // The task that yields was cancelled before yielding so the cancellation handler
                    // got invoked right away
                    cancelledAsyncProducers.append(writeToken.id)
                    self.state = .streaming(
                        backPressureStrategy: backPressureStrategy,
                        buffer: buffer,
                        consumerContinuation: consumerContinuation,
                        producerContinuations: producerContinuations,
                        cancelledAsyncProducers: cancelledAsyncProducers,
                        hasOutstandingDemand: hasOutstandingDemand,
                        iteratorInitialized: iteratorInitialized,
                        onTerminate: onTerminate
                    )

                    return .none
                }
                let continuation = producerContinuations.remove(at: index).1
                self.state = .streaming(
                    backPressureStrategy: backPressureStrategy,
                    buffer: buffer,
                    consumerContinuation: consumerContinuation,
                    producerContinuations: producerContinuations,
                    cancelledAsyncProducers: cancelledAsyncProducers,
                    hasOutstandingDemand: hasOutstandingDemand,
                    iteratorInitialized: iteratorInitialized,
                    onTerminate: onTerminate
                )

                return .resumeProducerWithCancellationError(continuation)

            case .sourceFinished, .finished:
                // Since we are unlocking between yielding and suspending the yield
                // It can happen that the source got finished or the consumption fully finishes.
                return .none
            }
        }

        /// Actions returned by `finish()`.
        @usableFromInline enum FinishAction {
            /// Indicates that the consumer continuation should be resumed with the failure, the producer continuations
            /// should be resumed with an error and `onTerminate` should be called.
            case resumeAllContinuationsAndCallOnTerminate(
                consumerContinuation: CheckedContinuation<Element?, any Error>,
                failure: Failure?,
                producerContinuations: [(Result<Void, any Error>) -> Void],
                onTerminate: (() -> Void)?
            )
            /// Indicates that the producer continuations should be resumed with an error.
            case resumeProducerContinuations(producerContinuations: [(Result<Void, any Error>) -> Void])
            /// Indicates that nothing should be done.
            case none
        }

        @inlinable mutating func finish(_ failure: Failure?) -> FinishAction {
            switch self.state {
            case .initial(_, let iteratorInitialized, let onTerminate):
                // TODO: Should we call onTerminate here
                // Nothing was yielded nor did anybody call next
                // This means we can transition to sourceFinished and store the failure
                self.state = .sourceFinished(
                    buffer: .init(),
                    iteratorInitialized: iteratorInitialized,
                    failure: failure,
                    onTerminate: onTerminate
                )

                return .none

            case .streaming(
                _,
                let buffer,
                .some(let consumerContinuation),
                let producerContinuations,
                _,
                _,
                let iteratorInitialized,
                let onTerminate
            ):
                // We have a continuation, this means our buffer must be empty
                // Furthermore, we can now transition to finished
                // and resume the continuation with the failure
                precondition(buffer.isEmpty, "Expected an empty buffer")

                self.state = .finished(iteratorInitialized: iteratorInitialized)

                return .resumeAllContinuationsAndCallOnTerminate(
                    consumerContinuation: consumerContinuation,
                    failure: failure,
                    producerContinuations: Array(producerContinuations.map { $0.1 }),
                    onTerminate: onTerminate
                )

            case .streaming(
                _,
                let buffer,
                consumerContinuation: .none,
                let producerContinuations,
                _,
                _,
                let iteratorInitialized,
                let onTerminate
            ):
                self.state = .sourceFinished(
                    buffer: buffer,
                    iteratorInitialized: iteratorInitialized,
                    failure: failure,
                    onTerminate: onTerminate
                )

                return .resumeProducerContinuations(producerContinuations: Array(producerContinuations.map { $0.1 }))

            case .sourceFinished, .finished:
                // If the source has finished, finishing again has no effect.
                return .none
            }
        }

        /// Actions returned by `next()`.
        enum NextAction {
            /// Indicates that the element should be returned to the caller.
            case returnElement(Element)
            /// Indicates that the element should be returned to the caller and that all producers should be called.
            case returnElementAndResumeProducers(Element, [(Result<Void, any Error>) -> Void])
            /// Indicates that the `Failure` should be returned to the caller and that `onTerminate` should be called.
            case returnFailureAndCallOnTerminate(Failure?, (() -> Void)?)
            /// Indicates that the `nil` should be returned to the caller.
            case returnNil
            /// Indicates that the `Task` of the caller should be suspended.
            case suspendTask
        }

        mutating func next() -> NextAction {
            switch self.state {
            case .initial(let backPressureStrategy, let iteratorInitialized, let onTerminate):
                // We are not interacting with the back-pressure strategy here because
                // we are doing this inside `next(:)`
                self.state = .streaming(
                    backPressureStrategy: backPressureStrategy,
                    buffer: Deque<Element>(),
                    consumerContinuation: nil,
                    producerContinuations: .init(),
                    cancelledAsyncProducers: .init(),
                    hasOutstandingDemand: false,
                    iteratorInitialized: iteratorInitialized,
                    onTerminate: onTerminate
                )

                return .suspendTask

            case .streaming(_, _, .some, _, _, _, _, _):
                // We have multiple AsyncIterators iterating the sequence
                preconditionFailure("This should never happen since we only allow a single Iterator to be created")

            case .streaming(
                var backPressureStrategy,
                var buffer,
                .none,
                var producerContinuations,
                let cancelledAsyncProducers,
                let hasOutstandingDemand,
                let iteratorInitialized,
                let onTerminate
            ):
                guard let element = buffer.popFirst() else {
                    // There is nothing in the buffer to fulfil the demand so we need to suspend.
                    // We are not interacting with the back-pressure strategy here because
                    // we are doing this inside `suspendNext`
                    self.state = .streaming(
                        backPressureStrategy: backPressureStrategy,
                        buffer: buffer,
                        consumerContinuation: nil,
                        producerContinuations: producerContinuations,
                        cancelledAsyncProducers: cancelledAsyncProducers,
                        hasOutstandingDemand: hasOutstandingDemand,
                        iteratorInitialized: iteratorInitialized,
                        onTerminate: onTerminate
                    )

                    return .suspendTask
                }
                // We have an element to fulfil the demand right away.

                let shouldProduceMore = backPressureStrategy.didConsume(element: element)

                guard shouldProduceMore else {
                    self.state = .streaming(
                        backPressureStrategy: backPressureStrategy,
                        buffer: buffer,
                        consumerContinuation: nil,
                        producerContinuations: producerContinuations,
                        cancelledAsyncProducers: cancelledAsyncProducers,
                        hasOutstandingDemand: shouldProduceMore,
                        iteratorInitialized: iteratorInitialized,
                        onTerminate: onTerminate
                    )
                    // We don't have any new demand, so we can just return the element.
                    return .returnElement(element)
                }
                let producers = Array(producerContinuations.map { $0.1 })
                producerContinuations.removeAll()
                self.state = .streaming(
                    backPressureStrategy: backPressureStrategy,
                    buffer: buffer,
                    consumerContinuation: nil,
                    producerContinuations: producerContinuations,
                    cancelledAsyncProducers: cancelledAsyncProducers,
                    hasOutstandingDemand: shouldProduceMore,
                    iteratorInitialized: iteratorInitialized,
                    onTerminate: onTerminate
                )
                return .returnElementAndResumeProducers(element, producers)

            case .sourceFinished(var buffer, let iteratorInitialized, let failure, let onTerminate):
                // Check if we have an element left in the buffer and return it
                guard let element = buffer.popFirst() else {
                    // We are returning the queued failure now and can transition to finished
                    self.state = .finished(iteratorInitialized: iteratorInitialized)

                    return .returnFailureAndCallOnTerminate(failure, onTerminate)
                }
                self.state = .sourceFinished(
                    buffer: buffer,
                    iteratorInitialized: iteratorInitialized,
                    failure: failure,
                    onTerminate: onTerminate
                )

                return .returnElement(element)

            case .finished: return .returnNil
            }
        }

        /// Actions returned by `suspendNext()`.
        enum SuspendNextAction {
            /// Indicates that the continuation should be resumed.
            case resumeContinuationWithElement(CheckedContinuation<Element?, any Error>, Element)
            /// Indicates that the continuation and all producers should be resumed.
            case resumeContinuationWithElementAndProducers(
                CheckedContinuation<Element?, any Error>,
                Element,
                [(Result<Void, any Error>) -> Void]
            )
            /// Indicates that the continuation should be resumed with the failure and that `onTerminate` should be called.
            case resumeContinuationWithFailureAndCallOnTerminate(
                CheckedContinuation<Element?, any Error>,
                Failure?,
                (() -> Void)?
            )
            /// Indicates that the continuation should be resumed with `nil`.
            case resumeContinuationWithNil(CheckedContinuation<Element?, any Error>)
            /// Indicates that nothing should be done.
            case none
        }

        mutating func suspendNext(continuation: CheckedContinuation<Element?, any Error>) -> SuspendNextAction {
            switch self.state {
            case .initial:
                // We need to transition to streaming before we can suspend
                preconditionFailure("Internal inconsistency")

            case .streaming(_, _, .some, _, _, _, _, _):
                // We have multiple AsyncIterators iterating the sequence
                preconditionFailure("This should never happen since we only allow a single Iterator to be created")

            case .streaming(
                var backPressureStrategy,
                var buffer,
                .none,
                var producerContinuations,
                let cancelledAsyncProducers,
                let hasOutstandingDemand,
                let iteratorInitialized,
                let onTerminate
            ):
                // We have to check here again since we might have a producer interleave next and suspendNext
                guard let element = buffer.popFirst() else {
                    // There is nothing in the buffer to fulfil the demand so we to store the continuation.
                    self.state = .streaming(
                        backPressureStrategy: backPressureStrategy,
                        buffer: buffer,
                        consumerContinuation: continuation,
                        producerContinuations: producerContinuations,
                        cancelledAsyncProducers: cancelledAsyncProducers,
                        hasOutstandingDemand: hasOutstandingDemand,
                        iteratorInitialized: iteratorInitialized,
                        onTerminate: onTerminate
                    )

                    return .none
                }
                // We have an element to fulfil the demand right away.

                let shouldProduceMore = backPressureStrategy.didConsume(element: element)

                guard shouldProduceMore else {
                    // We don't have any new demand, so we can just return the element.
                    return .resumeContinuationWithElement(continuation, element)
                }
                let producers = Array(producerContinuations.map { $0.1 })
                producerContinuations.removeAll()
                self.state = .streaming(
                    backPressureStrategy: backPressureStrategy,
                    buffer: buffer,
                    consumerContinuation: nil,
                    producerContinuations: producerContinuations,
                    cancelledAsyncProducers: cancelledAsyncProducers,
                    hasOutstandingDemand: shouldProduceMore,
                    iteratorInitialized: iteratorInitialized,
                    onTerminate: onTerminate
                )
                return .resumeContinuationWithElementAndProducers(continuation, element, producers)

            case .sourceFinished(var buffer, let iteratorInitialized, let failure, let onTerminate):
                // Check if we have an element left in the buffer and return it
                guard let element = buffer.popFirst() else {
                    // We are returning the queued failure now and can transition to finished
                    self.state = .finished(iteratorInitialized: iteratorInitialized)

                    return .resumeContinuationWithFailureAndCallOnTerminate(continuation, failure, onTerminate)
                }
                self.state = .sourceFinished(
                    buffer: buffer,
                    iteratorInitialized: iteratorInitialized,
                    failure: failure,
                    onTerminate: onTerminate
                )

                return .resumeContinuationWithElement(continuation, element)

            case .finished: return .resumeContinuationWithNil(continuation)
            }
        }

        /// Actions returned by `cancelNext()`.
        enum CancelNextAction {
            /// Indicates that the continuation should be resumed with a cancellation error, the producers should be finished and call onTerminate.
            case resumeContinuationWithCancellationErrorAndFinishProducersAndCallOnTerminate(
                CheckedContinuation<Element?, any Error>,
                [(Result<Void, any Error>) -> Void],
                (() -> Void)?
            )
            /// Indicates that the producers should be finished and call onTerminate.
            case finishProducersAndCallOnTerminate([(Result<Void, any Error>) -> Void], (() -> Void)?)
            /// Indicates that nothing should be done.
            case none
        }

        mutating func cancelNext() -> CancelNextAction {
            switch self.state {
            case .initial:
                // We need to transition to streaming before we can suspend
                preconditionFailure("Internal inconsistency")

            case .streaming(
                _,
                _,
                let consumerContinuation,
                let producerContinuations,
                _,
                _,
                let iteratorInitialized,
                let onTerminate
            ):
                self.state = .finished(iteratorInitialized: iteratorInitialized)

                guard let consumerContinuation = consumerContinuation else {
                    return .finishProducersAndCallOnTerminate(Array(producerContinuations.map { $0.1 }), onTerminate)
                }
                return .resumeContinuationWithCancellationErrorAndFinishProducersAndCallOnTerminate(
                    consumerContinuation,
                    Array(producerContinuations.map { $0.1 }),
                    onTerminate
                )

            case .sourceFinished, .finished: return .none
            }
        }
    }
}
