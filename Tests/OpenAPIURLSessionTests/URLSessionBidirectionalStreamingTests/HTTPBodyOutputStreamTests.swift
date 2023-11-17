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

import OpenAPIRuntime
import XCTest
@testable import OpenAPIURLSession

// swift-format-ignore: AllPublicDeclarationsHaveDocumentation
class HTTPBodyOutputStreamBridgeTests: XCTestCase {
    static override func setUp() { OpenAPIURLSession.debugLoggingEnabled = true }

    func testHTTPBodyOutputStreamInputOutput() async throws {
        let chunkSize = 71
        let streamBufferSize = 37
        let numBytes: UInt8 = .max

        // Create a HTTP body with one byte per chunk.
        let requestBytes = (0...numBytes).map { UInt8($0) }
        let requestChunks = requestBytes.chunks(of: chunkSize)
        let requestByteSequence = MockAsyncSequence(elementsToVend: requestChunks, gatingProduction: false)
        let requestBody = HTTPBody(requestByteSequence, length: .known(requestBytes.count), iterationBehavior: .single)

        // Create a pair of bound streams with a tiny buffer to be the bottleneck for backpressure.
        var inputStream: InputStream?
        var outputStream: OutputStream?
        Stream.getBoundStreams(withBufferSize: streamBufferSize, inputStream: &inputStream, outputStream: &outputStream)
        guard let inputStream, let outputStream else { fatalError("getBoundStreams did not return non-nil streams") }

        // Bridge the HTTP body to the output stream.
        let requestStream = HTTPBodyOutputStreamBridge(outputStream, requestBody)

        // Set up a mock delegate to drive the stream pair.
        let delegate = MockInputStreamDelegate(inputStream: inputStream)

        // Read all the data from the input stream using max bytes > stream buffer size.
        var data = [UInt8]()
        data.reserveCapacity(requestBytes.count)
        while let inputStreamBytes = try await delegate.waitForBytes(maxBytes: 4096) {
            data.append(contentsOf: inputStreamBytes)
        }
        XCTAssertEqual(data, requestBytes)

        // Check all bytes have been vended.
        XCTAssertEqual(requestByteSequence.elementsVended.count, requestByteSequence.elementsToVend.count)

        // Input stream delegate will have reached end of stream and closed the input stream.
        XCTAssertEqual(inputStream.streamStatus, .closed)
        XCTAssertNil(inputStream.streamError)

        // Check the output stream closes gracefully in response to the input stream closing.
        HTTPBodyOutputStreamBridge.streamQueue.asyncAndWait {
            XCTAssertEqual(requestStream.outputStream.streamStatus, .closed)
            XCTAssertNil(requestStream.outputStream.streamError)
        }
    }

    func testHTTPBodyOutputStreamBridgeBackpressure() async throws {
        let chunkSize = 71
        let streamBufferSize = 37
        let numBytes: UInt8 = .max

        // Create a HTTP body with one byte per chunk.
        let requestBytes = (0...numBytes).map { UInt8($0) }
        let requestChunks = requestBytes.chunks(of: chunkSize)
        let requestByteSequence = MockAsyncSequence(elementsToVend: requestChunks, gatingProduction: true)
        let requestBody = HTTPBody(requestByteSequence, length: .known(requestBytes.count), iterationBehavior: .single)

        // Create a pair of bound streams with a tiny buffer to be the bottleneck for backpressure.
        var inputStream: InputStream?
        var outputStream: OutputStream?
        Stream.getBoundStreams(withBufferSize: streamBufferSize, inputStream: &inputStream, outputStream: &outputStream)
        guard let inputStream, let outputStream else { fatalError("getBoundStreams did not return non-nil streams") }

        // Bridge the HTTP body to the output stream.
        let requestStream = HTTPBodyOutputStreamBridge(outputStream, requestBody)

        // Set up a mock delegate to drive the stream pair.
        let delegate = MockInputStreamDelegate(inputStream: inputStream)
        _ = delegate

        // Check both streams have been opened.
        XCTAssertEqual(outputStream.streamStatus, .open)
        XCTAssertEqual(inputStream.streamStatus, .open)

        // At this point, because our mock async sequence that's backing the output stream is gated:
        // - The mock async sequence has vended zero elements.
        // - The output stream bridge has read nothing from from the async sequence.
        // - The output stream bridge has written nothing to the output stream.
        // - The output stream should have space available, the entire size of the buffer.
        XCTAssert(requestByteSequence.elementsVended.isEmpty)
        XCTAssertEqual(outputStream.streamStatus, .open)
        //        XCTAssert(requestStream.bytesToWrite.isEmpty)
        XCTAssert(outputStream.hasSpaceAvailable)

        // Now we'll tell our mock sequence to let through as many bytes as it can.
        requestByteSequence.openGate()

        // After some time, the buffer will be full.
        let expectation = expectation(description: "output stream has no space available")
        HTTPBodyOutputStreamBridge.streamQueue.asyncAfter(deadline: .now() + .milliseconds(100)) {
            if !requestStream.outputStream.hasSpaceAvailable { expectation.fulfill() }
        }
        await fulfillment(of: [expectation], timeout: 0.5)

        // The underlying sequence should only have vended enough chunks to fill the buffer.
        XCTAssertEqual(requestByteSequence.elementsVended.count, (streamBufferSize - 1) / chunkSize + 1)
    }

    func testHTTPBodyOutputStreamPullThroughBufferOneByteBig() async throws {
        let chunkSize = 1
        let streamBufferSize = 1
        let numBytes: UInt8 = .max

        // Create a HTTP body with one byte per chunk.
        let requestBytes = (0...numBytes).map { UInt8($0) }
        let requestChunks = requestBytes.chunks(of: chunkSize)
        let requestByteSequence = MockAsyncSequence(elementsToVend: requestChunks, gatingProduction: true)
        let requestBody = HTTPBody(requestByteSequence, length: .known(requestBytes.count), iterationBehavior: .single)

        // Create a pair of bound streams with a tiny buffer to be the bottleneck for backpressure.
        var inputStream: InputStream?
        var outputStream: OutputStream?
        Stream.getBoundStreams(withBufferSize: streamBufferSize, inputStream: &inputStream, outputStream: &outputStream)
        guard let inputStream, let outputStream else { fatalError("getBoundStreams did not return non-nil streams") }

        // Bridge the HTTP body to the output stream.
        let requestStream = HTTPBodyOutputStreamBridge(outputStream, requestBody)

        // Set up a mock delegate to drive the stream pair.
        let delegate = MockInputStreamDelegate(inputStream: inputStream)

        // Read one byte at a time from the input sequence, which will make space in the buffer.
        for i in 0..<requestBytes.count {
            // check the async sequence underlying the output stream has only vended i bytes so far.
            XCTAssertEqual(requestByteSequence.elementsVended.count, i)
            // let one byte through the async sequence underlying the output stream.
            requestByteSequence.openGate(for: 1)
            // wait for one byte to be read by the bound input stream.
            let byte = try await delegate.waitForBytes(maxBytes: 1)?.first
            // check the byte is the expected byte from the initial request bytes.
            XCTAssertEqual(byte, requestBytes[i])
        }

        // Check all bytes have been vended, but the streams are still open.
        XCTAssertEqual(requestByteSequence.elementsVended.count, requestByteSequence.elementsToVend.count)
        XCTAssertEqual(inputStream.streamStatus, .open)
        XCTAssertEqual(requestStream.outputStream.streamStatus, .open)

        // After all bytes have been vended, the next byte should be nil, and streams should close gracefully.
        requestByteSequence.openGate()
        let byte = try await delegate.waitForBytes(maxBytes: 1)
        XCTAssertNil(byte)
        XCTAssertEqual(inputStream.streamStatus, .closed)
        XCTAssertNil(inputStream.streamError)

        // Check the output stream closes gracefully in response to the input stream closing.
        HTTPBodyOutputStreamBridge.streamQueue.sync {
            XCTAssertEqual(requestStream.outputStream.streamStatus, .closed)
            XCTAssertNil(requestStream.outputStream.streamError)
        }
    }

    func testHTTPBodyOutputStreamBridgeStreamClosedEarly() async throws {
        let chunkSize = 1
        let streamBufferSize = 1
        let numBytes: UInt8 = .max

        // Create a HTTP body with one byte per chunk.
        let requestBytes = (0...numBytes).map { UInt8($0) }
        let requestChunks = requestBytes.chunks(of: chunkSize)
        let requestByteSequence = MockAsyncSequence(elementsToVend: requestChunks, gatingProduction: true)
        let requestBody = HTTPBody(requestByteSequence, length: .known(requestBytes.count), iterationBehavior: .single)

        // Create a pair of bound streams with a tiny buffer to be the bottleneck for backpressure.
        var inputStream: InputStream?
        var outputStream: OutputStream?
        Stream.getBoundStreams(withBufferSize: streamBufferSize, inputStream: &inputStream, outputStream: &outputStream)
        guard let inputStream, let outputStream else { fatalError("getBoundStreams did not return non-nil streams") }

        // Bridge the HTTP body to the output stream.
        let requestStream = HTTPBodyOutputStreamBridge(outputStream, requestBody)

        // Set up a mock delegate to drive the stream pair.
        let delegate = MockInputStreamDelegate(inputStream: inputStream)

        // Write just half the bytes.
        requestByteSequence.openGate(for: requestBytes.count / 2)
        for i in 0..<requestBytes.count / 2 {
            // wait for one byte to be read by the bound input stream.
            let byte = try await delegate.waitForBytes(maxBytes: 1)?.first
            // check the byte is the expected byte from the initial request bytes.
            XCTAssertEqual(byte, requestBytes[i])
        }

        // With half the bytes written, the streams should still be open.
        XCTAssertEqual(requestByteSequence.elementsVended.count, requestByteSequence.elementsToVend.count / 2)
        XCTAssertEqual(inputStream.streamStatus, .open)
        XCTAssertEqual(requestStream.outputStream.streamStatus, .open)

        // Now we close the input stream (simulating the server closing the connection).
        delegate.close()
        XCTAssertEqual(inputStream.streamStatus, .closed)
        XCTAssertNil(inputStream.streamError)

        // Check the output stream closes gracefully in response to the input stream closing.
        let closeExpectation = expectation(description: "output stream is closed without error")
        HTTPBodyOutputStreamBridge.streamQueue.asyncAfter(deadline: .now() + .microseconds(100)) {
            XCTAssertEqual(requestStream.outputStream.streamStatus, .closed)
            XCTAssertNil(requestStream.outputStream.streamError)
            closeExpectation.fulfill()
        }
        await fulfillment(of: [closeExpectation], timeout: 0.1)

        // Any further calls to our mock delegate should yield nil.
        requestByteSequence.openGate()
        let byte = try await delegate.waitForBytes(maxBytes: 1)
        XCTAssertNil(byte)
    }

    func testHTTPBodyOutputStreamBridgeStreamClosedImmediately() async throws {
        let chunkSize = 71
        let streamBufferSize = 37
        let numBytes: UInt8 = .max

        // Create a HTTP body with one byte per chunk.
        let requestBytes = (0...numBytes).map { UInt8($0) }
        let requestChunks = requestBytes.chunks(of: chunkSize)
        let requestByteSequence = MockAsyncSequence(elementsToVend: requestChunks, gatingProduction: true)
        let requestBody = HTTPBody(requestByteSequence, length: .known(requestBytes.count), iterationBehavior: .single)

        // Create a pair of bound streams with a tiny buffer to be the bottleneck for backpressure.
        var inputStream: InputStream?
        var outputStream: OutputStream?
        Stream.getBoundStreams(withBufferSize: streamBufferSize, inputStream: &inputStream, outputStream: &outputStream)
        guard let inputStream, let outputStream else { fatalError("getBoundStreams did not return non-nil streams") }

        // Bridge the HTTP body to the output stream.
        let requestStream = HTTPBodyOutputStreamBridge(outputStream, requestBody)

        // Set up a mock delegate to drive the stream pair.
        let delegate = MockInputStreamDelegate(inputStream: inputStream)

        // Emit nothing, just close the input stream.
        XCTAssertEqual(inputStream.streamStatus, .open)
        XCTAssertEqual(requestStream.outputStream.streamStatus, .open)
        delegate.close()
        XCTAssertEqual(inputStream.streamStatus, .closed)
        XCTAssertNil(inputStream.streamError)

        // Check the output stream closes gracefully in response to the input stream closing.
        requestByteSequence.openGate()
        let closeExpectation = expectation(description: "output stream is closed without error")
        HTTPBodyOutputStreamBridge.streamQueue.asyncAfter(deadline: .now() + .microseconds(100)) {
            XCTAssertEqual(requestStream.outputStream.streamStatus, .closed)
            XCTAssertNil(requestStream.outputStream.streamError)
            closeExpectation.fulfill()
        }
        await fulfillment(of: [closeExpectation], timeout: 0.1)
    }
}

#endif  // canImport(Darwin)
