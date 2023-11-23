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
@testable import OpenAPIURLSession

/// Reads one byte at a time from the stream, regardless of how many bytes are available.
///
/// Used for testing the HTTPOutputStreamBridge backpressure behaviour, without URLSession.
final class MockInputStreamDelegate: NSObject, StreamDelegate {
    static let streamQueue = DispatchQueue(label: "MockInputStreamDelegate", autoreleaseFrequency: .workItem)

    private var inputStream: InputStream

    enum State {
        case noWaiter
        case haveWaiter(CheckedContinuation<[UInt8]?, any Error>, maxBytes: Int)
        case closed((any Error)?)
    }
    private(set) var state: State

    init(inputStream: InputStream) {
        self.inputStream = inputStream
        self.state = .noWaiter
        super.init()
        self.inputStream.delegate = self
        CFReadStreamSetDispatchQueue(self.inputStream as CFReadStream, Self.streamQueue)
        self.inputStream.open()
    }

    deinit { debug("Input stream delegate deinit") }

    private func readAndResumeContinuation() {
        dispatchPrecondition(condition: .onQueue(Self.streamQueue))
        guard case .haveWaiter(let continuation, let maxBytes) = state else {
            preconditionFailure("Invalid state: \(state)")
        }
        guard inputStream.hasBytesAvailable else { return }
        let buffer = [UInt8](unsafeUninitializedCapacity: maxBytes) { buffer, count in
            count = inputStream.read(buffer.baseAddress!, maxLength: maxBytes)
        }
        switch buffer.count {
        case -1:
            debug("Input stream delegate error reading from stream: \(inputStream.streamError!)")
            inputStream.close()
            continuation.resume(throwing: inputStream.streamError!)
        case 0:
            debug("Input stream delegate reached end of stream; will close stream")
            self.close()
            continuation.resume(returning: nil)
        case let numBytesRead where numBytesRead > 0:
            debug("Input stream delegate read \(numBytesRead) bytes from stream: \(buffer)")
            continuation.resume(returning: buffer)
        default: preconditionFailure()
        }
        state = .noWaiter
    }

    func waitForBytes(maxBytes: Int) async throws -> [UInt8]? {
        if inputStream.streamStatus == .closed {
            state = .closed(inputStream.streamError)
            guard let error = inputStream.streamError else { return nil }
            throw error
        }
        return try await withCheckedThrowingContinuation { continuation in
            Self.streamQueue.async {
                guard case .noWaiter = self.state else { preconditionFailure() }
                self.state = .haveWaiter(continuation, maxBytes: maxBytes)
                self.readAndResumeContinuation()
            }
        }
    }

    func close(withError error: (any Error)? = nil) {
        self.inputStream.close()
        Self.streamQueue.async { self.state = .closed(error) }
        debug("Input stream delegate closed stream with error: \(String(describing: error))")
    }

    func stream(_ stream: Stream, handle event: Stream.Event) {
        dispatchPrecondition(condition: .onQueue(Self.streamQueue))
        debug("Input stream delegate received event: \(event)")
        switch event {
        case .hasBytesAvailable:
            switch state {
            case .haveWaiter: readAndResumeContinuation()
            case .noWaiter: break
            case .closed: preconditionFailure()
            }
        case .errorOccurred: self.close()
        default: break
        }
    }
}

extension MockInputStreamDelegate: @unchecked Sendable {}  // State synchronized using DispatchQueue.

#endif  // canImport(Darwin)
