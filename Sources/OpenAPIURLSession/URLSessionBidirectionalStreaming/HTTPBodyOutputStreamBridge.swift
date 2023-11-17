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
import OpenAPIRuntime
import HTTPTypes
#if canImport(Darwin)
import Foundation

final class HTTPBodyOutputStreamBridge: NSObject, StreamDelegate {
    static let streamQueue = DispatchQueue(label: "HTTPBodyStreamDelegate", autoreleaseFrequency: .workItem)

    let httpBody: HTTPBody
    let outputStream: OutputStream
    private(set) var state: State {
        didSet { debug("Output stream delegate state transition: \(oldValue) -> \(state)") }
    }

    /// Creates a new `HTTPBodyOutputStreamBridge` and opens the output stream.
    init(_ outputStream: OutputStream, _ httpBody: HTTPBody) {
        self.httpBody = httpBody
        self.outputStream = outputStream
        self.state = .initial
        super.init()
        self.outputStream.delegate = self
        CFWriteStreamSetDispatchQueue(self.outputStream as CFWriteStream, Self.streamQueue)
        self.outputStream.open()
    }

    deinit { debug("Output stream delegate deinit") }

    func performAction(_ action: State.Action) {
        debug("Output stream delegate performing action from state machine: \(action)")
        dispatchPrecondition(condition: .onQueue(Self.streamQueue))
        switch action {
        case .none: return
        case .resumeProducer(let producerContinuation):
            producerContinuation.resume()
            performAction(self.state.resumedProducer())
        case .writeBytes(let chunk): writePendingBytes(chunk)
        case .cancelProducerAndCloseStream(let producerContinuation):
            producerContinuation.resume(throwing: CancellationError())
            outputStream.close()
        case .cancelProducer(let producerContinuation): producerContinuation.resume(throwing: CancellationError())
        case .closeStream: outputStream.close()
        }
    }

    func startWriterTask() {
        dispatchPrecondition(condition: .onQueue(Self.streamQueue))
        let task = Task {
            dispatchPrecondition(condition: .notOnQueue(Self.streamQueue))
            for try await chunk in httpBody {
                try await withCheckedThrowingContinuation { continuation in
                    Self.streamQueue.async {
                        debug("Output stream delegate produced chunk and suspended producer.")
                        self.performAction(self.state.producedChunkAndSuspendedProducer(chunk, continuation))
                    }
                }
            }
            Self.streamQueue.async {
                debug("Output stream delegate wrote final chunk.")
                self.performAction(self.state.wroteFinalChunk())
            }
        }
        self.performAction(self.state.startedProducerTask(task))
    }

    private func writePendingBytes(_ bytesToWrite: Chunk) {
        dispatchPrecondition(condition: .onQueue(Self.streamQueue))
        precondition(!bytesToWrite.isEmpty, "\(#function) must be called with non-empty bytes")
        guard outputStream.streamStatus == .open else {
            debug("Output stream closed unexpectedly.")
            performAction(self.state.wroteBytes(numBytesWritten: 0, streamStillHasSpaceAvailable: false))
            return
        }
        switch bytesToWrite.withUnsafeBytes({ outputStream.write($0.baseAddress!, maxLength: bytesToWrite.count) }) {
        case 0:
            debug("Output stream delegate reached end of stream when writing.")
            performAction(self.state.endEncountered())
        case -1:
            debug("Output stream delegate encountered error writing to stream: \(outputStream.streamError!).")
            performAction(self.state.errorOccurred(outputStream.streamError!))
        case let written where written > 0:
            debug("Output stream delegate wrote \(written) bytes to stream.")
            performAction(
                self.state.wroteBytes(
                    numBytesWritten: written,
                    streamStillHasSpaceAvailable: outputStream.hasSpaceAvailable
                )
            )
        default: preconditionFailure("OutputStream.write(_:maxLength:) returned undocumented value")
        }
    }

    func stream(_ stream: Stream, handle event: Stream.Event) {
        dispatchPrecondition(condition: .onQueue(Self.streamQueue))
        debug("Output stream delegate received event: \(event).")
        switch event {
        case .openCompleted:
            guard case .initial = state else {
                debug("Output stream delegate ignoring duplicate openCompleted event.")
                return
            }
            startWriterTask()
        case .hasSpaceAvailable: performAction(self.state.spaceBecameAvailable())
        case .errorOccurred: performAction(self.state.errorOccurred(stream.streamError!))
        case .endEncountered: performAction(self.state.endEncountered())
        default:
            debug("Output stream ignoring event: \(event).")
            break
        }
    }
}

extension HTTPBodyOutputStreamBridge {
    typealias Chunk = ArraySlice<UInt8>
    typealias ProducerTask = Task<Void, any Error>
    typealias ProducerContinuation = CheckedContinuation<Void, any Error>

    enum State {
        case initial
        case waitingForBytes(spaceAvailable: Bool)
        case haveBytes(spaceAvailable: Bool, Chunk, ProducerContinuation)
        case needBytes(spaceAvailable: Bool, ProducerContinuation)
        case closed((any Error)?)

        mutating func startedProducerTask(_ producerTask: ProducerTask) -> Action {
            switch self {
            case .initial:
                self = .waitingForBytes(spaceAvailable: false)
                return .none
            case .waitingForBytes, .haveBytes, .needBytes, .closed:
                preconditionFailure("\(#function) called in invalid state: \(self)")
            }
        }

        mutating func producedChunkAndSuspendedProducer(_ chunk: Chunk, _ producerContinuation: ProducerContinuation)
            -> Action
        {
            switch self {
            case .waitingForBytes(let spaceAvailable):
                self = .haveBytes(spaceAvailable: spaceAvailable, chunk, producerContinuation)
                guard spaceAvailable else { return .none }
                return .writeBytes(chunk)
            case .closed: return .cancelProducer(producerContinuation)
            case .initial, .haveBytes, .needBytes: preconditionFailure("\(#function) called in invalid state: \(self)")
            }
        }

        mutating func wroteBytes(numBytesWritten: Int, streamStillHasSpaceAvailable: Bool) -> Action {
            switch self {
            case .haveBytes(let spaceAvailable, let chunk, let producerContinuation):
                guard spaceAvailable, numBytesWritten <= chunk.count else { preconditionFailure() }
                let remaining = chunk.dropFirst(numBytesWritten)
                guard remaining.isEmpty else {
                    self = .haveBytes(spaceAvailable: streamStillHasSpaceAvailable, remaining, producerContinuation)
                    guard streamStillHasSpaceAvailable else { return .none }
                    return .writeBytes(remaining)
                }
                self = .needBytes(spaceAvailable: streamStillHasSpaceAvailable, producerContinuation)
                return .resumeProducer(producerContinuation)
            case .initial, .needBytes, .waitingForBytes, .closed:
                preconditionFailure("\(#function) called in invalid state: \(self)")
            }
        }

        mutating func resumedProducer() -> Action {
            switch self {
            case .needBytes(let spaceAvailable, _):
                self = .waitingForBytes(spaceAvailable: spaceAvailable)
                return .none
            case .initial, .haveBytes, .waitingForBytes, .closed:
                preconditionFailure("\(#function) called in invalid state: \(self)")
            }
        }

        mutating func errorOccurred(_ error: any Error) -> Action {
            switch self {
            case .initial:
                self = .closed(error)
                return .none
            case .waitingForBytes(_):
                self = .closed(error)
                return .closeStream
            case .haveBytes(_, _, let producerContinuation):
                self = .closed(error)
                return .cancelProducerAndCloseStream(producerContinuation)
            case .needBytes(_, let producerContinuation):
                self = .closed(error)
                return .cancelProducerAndCloseStream(producerContinuation)
            case .closed: preconditionFailure("\(#function) called in invalid state: \(self)")
            }
        }

        mutating func wroteFinalChunk() -> Action {
            switch self {
            case .waitingForBytes(_):
                self = .closed(nil)
                return .closeStream
            case .initial, .haveBytes, .needBytes, .closed:
                preconditionFailure("\(#function) called in invalid state: \(self)")
            }
        }

        mutating func endEncountered() -> Action {
            switch self {
            case .waitingForBytes(_):
                self = .closed(nil)
                return .closeStream
            case .haveBytes(_, _, let producerContinuation):
                self = .closed(nil)
                return .cancelProducerAndCloseStream(producerContinuation)
            case .needBytes(_, let producerContinuation):
                self = .closed(nil)
                return .cancelProducerAndCloseStream(producerContinuation)
            case .initial, .closed: preconditionFailure("\(#function) called in invalid state: \(self)")
            }
        }

        mutating func spaceBecameAvailable() -> Action {
            switch self {
            case .waitingForBytes(_):
                self = .waitingForBytes(spaceAvailable: true)
                return .none
            case .haveBytes(_, let chunk, let producerContinuation):
                self = .haveBytes(spaceAvailable: true, chunk, producerContinuation)
                return .writeBytes(chunk)
            case .needBytes(_, let producerContinuation):
                self = .needBytes(spaceAvailable: true, producerContinuation)
                return .none
            case .closed:
                debug("Ignoring space available event in closed state")
                return .none
            case .initial: preconditionFailure("\(#function) called in invalid state: \(self)")
            }
        }

        enum Action {
            case none
            case resumeProducer(ProducerContinuation)
            case writeBytes(Chunk)
            case cancelProducerAndCloseStream(ProducerContinuation)
            case cancelProducer(ProducerContinuation)
            case closeStream
        }
    }
}

extension HTTPBodyOutputStreamBridge: @unchecked Sendable {}  // State synchronized using DispatchQueue.

extension HTTPBodyOutputStreamBridge.State: CustomStringConvertible {
    var description: String {
        switch self {
        case .initial: return "initial"
        case .waitingForBytes(let spaceAvailable): return "waitingForBytes(spaceAvailable: \(spaceAvailable))"
        case .haveBytes(let spaceAvailable, let chunk, _):
            return "haveBytes(spaceAvailable: \(spaceAvailable), [\(chunk.count) bytes])"
        case .needBytes(let spaceAvailable, _): return "needBytes (spaceAvailable: \(spaceAvailable), _)"
        case .closed(let error): return "closed (error: \(String(describing: error)))"
        }
    }
}

extension HTTPBodyOutputStreamBridge.State.Action: CustomStringConvertible {
    var description: String {
        switch self {
        case .none: return "none"
        case .resumeProducer: return "resumeProducer"
        case .writeBytes: return "writeBytes"
        case .cancelProducerAndCloseStream: return "cancelProducerAndCloseStream"
        case .cancelProducer: return "cancelProducer"
        case .closeStream: return "closeStream"
        }
    }
}

#endif  // canImport(Darwin)
