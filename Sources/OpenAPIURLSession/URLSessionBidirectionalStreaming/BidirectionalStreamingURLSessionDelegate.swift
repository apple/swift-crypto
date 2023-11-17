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

/// Delegate that supports bidirectional streaming of request and response bodies.
///
/// While URLSession provides a high-level API that returns an async sequence of
/// bytes, `bytes(for:delegate:)`, but does not provide an API that takes an async sequence
/// as a request body. For instance, `upload(for:delegate:)` and `upload(fromFile:delegate:)`
/// both buffer the entire response body and return `Data`.
///
/// Additionally, bridging `URLSession.AsyncBytes`, which is an `AsyncSequence<UInt8>` to
/// `OpenAPIRuntime.HTTPBody`, an `AsyncSequence<ByteChunk>`, is problematic and will
/// incur an allocation for every byte.
///
/// This delegate vends the response body as a `HTTBody` with one chunk for each
/// `urlSession(_:didReceive data:)` callback. It also provides backpressure, which will
/// suspend and resume the URLSession task based on a configurable high and low watermark.
///
/// When performing requests without a body, this delegate should be used with a
/// `URLSessionDataTask` to stream the response body.
///
/// When performing requests with a body, this delegate should be used with a
/// `URLSessionUploadTask` using `uploadTask(withStreamedRequest:delegate:)`, which will
/// ask the delegate for a `InputStream` for the request body via the
/// `urlSession(_:needNewBodyStreamForTask:)` callback.
///
/// The `urlSession(_:needNewBodyStreamForTask:)` callback will create a pair of bound
/// streams, bridge the `HTTPBody` request body to the `OutputStream` and return the
/// `InputStream` to URLSession. Backpressure for the request body stream is provided
/// as an implementation detail of how URLSession reads from the `InputStream`.
///
/// Note that `urlSession(_:needNewBodyStreamForTask:)` may be called more than once, e.g.
/// when performing a HTTP redirect, upon which the delegate is expected to create a new
/// `InputStream` for the request body. This is only possible if the underlying `HTTPBody`
/// request body can be iterated multiple times, i.e. `iterationBehavior == .multiple`.
/// If the request body cannot be iterated multiple times, then the URLSession task will be cancelled.
final class BidirectionalStreamingURLSessionDelegate: NSObject, URLSessionTaskDelegate, URLSessionDataDelegate {

    let requestBody: HTTPBody?
    var hasAlreadyIteratedRequestBody: Bool
    var hasSuspendedURLSessionTask: Bool
    let requestStreamBufferSize: Int
    var requestStream: HTTPBodyOutputStreamBridge?

    typealias ResponseContinuation = CheckedContinuation<URLResponse, any Error>
    var responseContinuation: ResponseContinuation?

    typealias ResponseBodyStream = AsyncBackpressuredStream<HTTPBody.ByteChunk, any Error>
    var responseBodyStream: ResponseBodyStream
    var responseBodyStreamSource: ResponseBodyStream.Source

    /// This lock is taken for the duration of all delegate callbacks to protect the mutable delegate state.
    ///
    /// Although all the delegate callbacks are performed on the session's `delegateQueue`, there is no guarantee that
    /// this is a _serial_ queue.
    ///
    /// Regardless of the type of delegate queue, URLSession will attempt to order the callbacks for each task in a
    /// sensible way, but it cannot be guaranteed, specifically when the URLSession task is cancelled.
    ///
    /// Therefore, even though the `suspend()`, `resume()`, and `cancel()` URLSession methods are thread-safe, we need
    /// to protect any mutable state within the delegate itself.
    let callbackLock = NIOLock()

    /// In addition to the callback lock, there is one point of rentrancy, where the response stream callback gets fired
    /// immediately, for this we have a different lock, which protects `hasSuspendedURLSessionTask`.
    let hasSuspendedURLSessionTaskLock = NIOLock()

    /// Use `bidirectionalStreamingRequest(for:baseURL:requestBody:requestStreamBufferSize:responseStreamWatermarks:)`.
    init(requestBody: HTTPBody?, requestStreamBufferSize: Int, responseStreamWatermarks: (low: Int, high: Int)) {
        self.requestBody = requestBody
        self.hasAlreadyIteratedRequestBody = false
        self.hasSuspendedURLSessionTask = false
        self.requestStreamBufferSize = requestStreamBufferSize
        (self.responseBodyStream, self.responseBodyStreamSource) = AsyncBackpressuredStream.makeStream(
            backPressureStrategy: .highLowWatermarkWithElementCounts(
                lowWatermark: responseStreamWatermarks.low,
                highWatermark: responseStreamWatermarks.high
            )
        )
    }

    func urlSession(_ session: URLSession, needNewBodyStreamForTask task: URLSessionTask) async -> InputStream? {
        callbackLock.withLock {
            debug("Task delegate: needNewBodyStreamForTask")
            // If the HTTP body cannot be iterated multiple times then bad luck; the only thing
            // we can do is cancel the task and return nil.
            if hasAlreadyIteratedRequestBody {
                guard requestBody!.iterationBehavior == .multiple else {
                    debug("Task delegate: Cannot rewind request body, cancelling task")
                    task.cancel()
                    return nil
                }
            }
            hasAlreadyIteratedRequestBody = true

            // Create a fresh pair of streams.
            let (inputStream, outputStream) = createStreamPair(withBufferSize: requestStreamBufferSize)

            // Bridge the output stream to the request body (which opens the output stream).
            requestStream = HTTPBodyOutputStreamBridge(outputStream, requestBody!)

            // Return the new input stream (unopened, it gets opened by URLSession).
            return inputStream
        }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        callbackLock.withLock {
            debug("Task delegate: didReceive data (numBytes: \(data.count))")
            do {
                switch try responseBodyStreamSource.write(contentsOf: CollectionOfOne(ArraySlice(data))) {
                case .produceMore: break
                case .enqueueCallback(let writeToken):
                    let shouldActuallyEnqueueCallback = hasSuspendedURLSessionTaskLock.withLock {
                        if hasSuspendedURLSessionTask {
                            debug("Task delegate: already suspended task, not enqueing another writer callback")
                            return false
                        }
                        debug("Task delegate: response stream backpressure, suspending task and enqueing callback")
                        dataTask.suspend()
                        hasSuspendedURLSessionTask = true
                        return true
                    }
                    if shouldActuallyEnqueueCallback {
                        responseBodyStreamSource.enqueueCallback(writeToken: writeToken) { result in
                            self.hasSuspendedURLSessionTaskLock.withLock {
                                switch result {
                                case .success:
                                    debug("Task delegate: response stream callback, resuming task")
                                    dataTask.resume()
                                    self.hasSuspendedURLSessionTask = false
                                case .failure(let error):
                                    debug("Task delegate: response stream callback, cancelling task, error: \(error)")
                                    dataTask.cancel()
                                }
                            }
                        }
                    }
                }
            } catch {
                debug("Task delegate: response stream consumer terminated, cancelling task")
                dataTask.cancel()
            }
        }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse) async
        -> URLSession.ResponseDisposition
    {
        callbackLock.withLock {
            debug("Task delegate: didReceive response")
            self.responseContinuation?.resume(returning: response)
            return .allow
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        callbackLock.withLock {
            debug("Task delegate: didCompleteWithError (error: \(String(describing: error)))")
            responseBodyStreamSource.finish(throwing: error)
            if let error { responseContinuation?.resume(throwing: error) }
        }
    }
}

extension BidirectionalStreamingURLSessionDelegate: @unchecked Sendable {}  // State synchronized using DispatchQueue.

private func createStreamPair(withBufferSize bufferSize: Int) -> (InputStream, OutputStream) {
    var inputStream: InputStream?
    var outputStream: OutputStream?
    Stream.getBoundStreams(withBufferSize: bufferSize, inputStream: &inputStream, outputStream: &outputStream)
    guard let inputStream, let outputStream else { fatalError("getBoundStreams did not return non-nil streams") }
    return (inputStream, outputStream)
}

#endif  // canImport(Darwin)
