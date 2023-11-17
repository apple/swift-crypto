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
import HTTPTypes
import NIO
import NIOHTTP1
import OpenAPIRuntime
import XCTest
@testable import OpenAPIURLSession

class URLSessionBidirectionalStreamingTests: XCTestCase {
    // swift-format-ignore: AllPublicDeclarationsHaveDocumentation
    static override func setUp() { OpenAPIURLSession.debugLoggingEnabled = true }

    func testBidirectionalEcho_PerChunkRatchet_1BChunk_1Chunks_1BUploadBuffer_1BDownloadWatermark() async throws {
        try await testBidirectionalEchoPerChunkRatchet(
            requestBodyChunk: Array(repeating: UInt8(ascii: "*"), count: 1)[...],
            numRequestBodyChunks: 1,
            uploadBufferSize: 1,
            responseStreamWatermarks: (low: 1, high: 1)
        )
    }

    func testBidirectionalEcho_PerChunkRatchet_1BChunk_10Chunks_1BUploadBuffer_1BDownloadWatermark() async throws {
        try await testBidirectionalEchoPerChunkRatchet(
            requestBodyChunk: Array(repeating: UInt8(ascii: "*"), count: 1)[...],
            numRequestBodyChunks: 10,
            uploadBufferSize: 1,
            responseStreamWatermarks: (low: 1, high: 1)
        )
    }

    func testBidirectionalEcho_PerChunkRatchet_1BChunk_10Chunks_10BUploadBuffer_1BDownloadWatermark() async throws {
        try await testBidirectionalEchoPerChunkRatchet(
            requestBodyChunk: Array(repeating: UInt8(ascii: "*"), count: 1)[...],
            numRequestBodyChunks: 10,
            uploadBufferSize: 10,
            responseStreamWatermarks: (low: 1, high: 1)
        )
    }

    func testBidirectionalEcho_PerChunkRatchet_1BChunk_10Chunks_1BUploadBuffer_10BDownloadWatermark() async throws {
        try await testBidirectionalEchoPerChunkRatchet(
            requestBodyChunk: Array(repeating: UInt8(ascii: "*"), count: 1)[...],
            numRequestBodyChunks: 10,
            uploadBufferSize: 1,
            responseStreamWatermarks: (low: 10, high: 10)
        )
    }

    func testBidirectionalEcho_PerChunkRatchet_1BChunk_10Chunks_10BUploadBuffer_10BDownloadWatermark() async throws {
        try await testBidirectionalEchoPerChunkRatchet(
            requestBodyChunk: Array(repeating: UInt8(ascii: "*"), count: 1)[...],
            numRequestBodyChunks: 10,
            uploadBufferSize: 10,
            responseStreamWatermarks: (low: 10, high: 10)
        )
    }

    func testBidirectionalEcho_PerChunkRatchet_10BChunk_10Chunks_1BUploadBuffer_1BDownloadWatermark() async throws {
        try await testBidirectionalEchoPerChunkRatchet(
            requestBodyChunk: Array(repeating: UInt8(ascii: "*"), count: 10)[...],
            numRequestBodyChunks: 10,
            uploadBufferSize: 1,
            responseStreamWatermarks: (low: 1, high: 1)
        )
    }

    func testBidirectionalEcho_PerChunkRatchet_10BChunk_10Chunks_10BUploadBuffer_1BDownloadWatermark() async throws {
        try await testBidirectionalEchoPerChunkRatchet(
            requestBodyChunk: Array(repeating: UInt8(ascii: "*"), count: 10)[...],
            numRequestBodyChunks: 10,
            uploadBufferSize: 10,
            responseStreamWatermarks: (low: 1, high: 1)
        )
    }

    func testBidirectionalEcho_PerChunkRatchet_10BChunk_10Chunks_1BUploadBuffer_10BDownloadWatermark() async throws {
        try await testBidirectionalEchoPerChunkRatchet(
            requestBodyChunk: Array(repeating: UInt8(ascii: "*"), count: 10)[...],
            numRequestBodyChunks: 10,
            uploadBufferSize: 1,
            responseStreamWatermarks: (low: 10, high: 10)
        )
    }

    func testBidirectionalEcho_PerChunkRatchet_10BChunk_10Chunks_10BUploadBuffer_10BDownloadWatermark() async throws {
        try await testBidirectionalEchoPerChunkRatchet(
            requestBodyChunk: Array(repeating: UInt8(ascii: "*"), count: 10)[...],
            numRequestBodyChunks: 10,
            uploadBufferSize: 10,
            responseStreamWatermarks: (low: 10, high: 10)
        )
    }

    func testBidirectionalEcho_PerChunkRatchet_4kChunk_10Chunks_16kUploadBuffer_4kDownloadWatermark() async throws {
        try await testBidirectionalEchoPerChunkRatchet(
            requestBodyChunk: Array(repeating: UInt8(ascii: "*"), count: 4 * 1024)[...],
            numRequestBodyChunks: 10,
            uploadBufferSize: 16 * 1024,
            responseStreamWatermarks: (low: 4096, high: 4096)
        )
    }

    func testBidirectionalEcho_PerChunkRatchet_1MChunk_10Chunks_16kUploadBuffer_4kDownloadWatermark() async throws {
        try await testBidirectionalEchoPerChunkRatchet(
            requestBodyChunk: Array(repeating: UInt8(ascii: "*"), count: 1 * 1024 * 1024)[...],
            numRequestBodyChunks: 10,
            uploadBufferSize: 16 * 1024,
            responseStreamWatermarks: (low: 4096, high: 4096)
        )
    }

    func testBidirectionalEcho_PerChunkRatchet_10MChunk_10Chunks_1MUploadBuffer_1MDownloadWatermark() async throws {
        try await testBidirectionalEchoPerChunkRatchet(
            requestBodyChunk: Array(repeating: UInt8(ascii: "*"), count: 10 * 1024 * 1024)[...],
            numRequestBodyChunks: 10,
            uploadBufferSize: 1 * 1024 * 1024,
            responseStreamWatermarks: (low: 1 * 1024 * 1024, high: 1 * 1024 * 1024)
        )
    }

    func testBidirectionalEcho_PerChunkRatchet_100kChunk_100Chunks_1MUploadBuffer_1MDownloadWatermark() async throws {
        try await testBidirectionalEchoPerChunkRatchet(
            requestBodyChunk: Array(repeating: UInt8(ascii: "*"), count: 100 * 1024)[...],
            numRequestBodyChunks: 100,
            uploadBufferSize: 1 * 1024 * 1024,
            responseStreamWatermarks: (low: 1 * 1024 * 1024, high: 1 * 1024 * 1024)
        )
    }

    func testBidirectionalEchoPerChunkRatchet(
        requestBodyChunk: HTTPBody.ByteChunk,
        numRequestBodyChunks: Int,
        uploadBufferSize: Int,
        responseStreamWatermarks: (low: Int, high: Int)
    ) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            // Server task.
            let serverPort = try await AsyncTestHTTP1Server.start(connectionTaskGroup: &group) { connectionChannel in
                try await connectionChannel.executeThenClose { inbound, outbound in
                    for try await requestPart in inbound {
                        switch requestPart {
                        case .head(_):
                            try await outbound.write(
                                .head(
                                    .init(
                                        version: .http1_1,
                                        status: .ok,
                                        headers: ["Content-Type": "application/octet-stream"]
                                    )
                                )
                            )
                        case .body(let buffer): try await outbound.write(.body(buffer))
                        case .end(_): try await outbound.write(.end(nil))
                        }
                    }
                }
            }

            // Set up the request body.
            let (requestBodyStream, requestBodyStreamContinuation) = AsyncStream<HTTPBody.ByteChunk>.makeStream()
            let requestBody = HTTPBody(requestBodyStream, length: .unknown, iterationBehavior: .single)

            // Start the request.
            async let asyncResponse = URLSession.shared.bidirectionalStreamingRequest(
                for: HTTPRequest(
                    method: .post,
                    scheme: nil,
                    authority: nil,
                    path: "/some/path",
                    headerFields: [.contentType: "application/octet-stream"]
                ),
                baseURL: URL(string: "http://127.0.0.1:\(serverPort)")!,
                requestBody: requestBody,
                requestStreamBufferSize: uploadBufferSize,
                responseStreamWatermarks: responseStreamWatermarks
            )

            /// At this point in the test, the server has sent the response head, which can be verified in Wireshark.
            ///
            /// A quirk of URLSession is that it won't fire the `didReceive response` callback, even if it has received
            /// the response head, until it has received at least one body byte, even when the server response headers
            /// indicate that the content-type is `application/octet-stream` and the transfer encoding is chunked.
            ///
            /// It's also worth noting that URLSession implements content sniffing so, if the content-type is absent,
            /// it will not call the `didReceive response` callback until it has received many more bytes.
            ///
            /// Additionally, there's no requirement on client libraries (or any intermediaries) to deliver partial
            /// responses to users, so the ability to affect this particular request response pattern entirely depends
            /// on the implementation details of the HTTP client libary.
            ///
            /// So... we send the first request chunk here, and have the server echo it back.
            requestBodyStreamContinuation.yield(requestBodyChunk)

            // We can now get the response head and the response body stream.
            let (response, responseBody) = try await asyncResponse
            XCTAssertEqual(response.status, .ok)

            // Consume and verify the first response chunk.
            var responseBodyIterator = responseBody!.makeAsyncIterator()
            var pendingExpectedResponseBytes = requestBodyChunk
            while !pendingExpectedResponseBytes.isEmpty {
                let responseBodyChunk = try await responseBodyIterator.next()!
                XCTAssertEqual(responseBodyChunk, pendingExpectedResponseBytes.prefix(responseBodyChunk.count))
                pendingExpectedResponseBytes.removeFirst(responseBodyChunk.count)
            }

            // Send the remaining request chunks, one at a time, and check the echoed response chunk.
            for _ in 1..<numRequestBodyChunks {
                requestBodyStreamContinuation.yield(requestBodyChunk)
                var pendingExpectedResponseBytes = requestBodyChunk
                while !pendingExpectedResponseBytes.isEmpty {
                    let responseBodyChunk = try await responseBodyIterator.next()!
                    XCTAssertEqual(responseBodyChunk, pendingExpectedResponseBytes.prefix(responseBodyChunk.count))
                    pendingExpectedResponseBytes.removeFirst(responseBodyChunk.count)
                }
            }

            // Terminate the request body stream.
            requestBodyStreamContinuation.finish()
            try await XCTAssertNilAsync(try await responseBodyIterator.next())

            group.cancelAll()
        }
    }

    func testStreamingDownload_1kChunk_10kChunks_100BDownloadWatermark() async throws {
        try await testStreamingDownload(
            responseChunk: (1...1024).map { _ in .random(in: (.min..<(.max))) }[...],
            numResponseChunks: 10_000,
            responseStreamWatermarks: (low: 100, high: 100),
            verification: .full
        )
    }

    func testStreamingDownload_10kChunk_1kChunks_100BDownloadWatermark() async throws {
        try await testStreamingDownload(
            responseChunk: (1...10 * 1024).map { _ in .random(in: (.min..<(.max))) }[...],
            numResponseChunks: 1_000,
            responseStreamWatermarks: (low: 100, high: 100),
            verification: .full
        )
    }

    func testStreamingDownload_100kChunk_100Chunks_100BDownloadWatermark() async throws {
        try await testStreamingDownload(
            responseChunk: (1...100 * 1024).map { _ in .random(in: (.min..<(.max))) }[...],
            numResponseChunks: 100,
            responseStreamWatermarks: (low: 100, high: 100),
            verification: .full
        )
    }

    func testStreamingDownload_1MChunk_10Chunks_10BDownloadWatermark() async throws {
        try await testStreamingDownload(
            responseChunk: (1...1024 * 1024).map { _ in .random(in: (.min..<(.max))) }[...],
            numResponseChunks: 10,
            responseStreamWatermarks: (low: 100, high: 100),
            verification: .full
        )
    }

    // Pulls 10GB of data through ~10MB of buffers.
    func testStreamingDownload_1MChunk_10kChunks_10MDownloadWatermark_CountOnly() async throws {
        try await testStreamingDownload(
            responseChunk: (1...1024 * 1024).map { _ in .random(in: (.min..<(.max))) }[...],
            numResponseChunks: 10_000,
            responseStreamWatermarks: (low: 10 * 1024 * 1024, high: 10 * 1024 * 1024),
            verification: .count
        )
    }

    // Same, but this time we add some delay in the processing, which should produce back pressure.
    // It does produce backpressure initially, then URLSession just lets rip with all the data.
    func testStreamingDownload_1MChunk_10kChunks_10MDownloadWatermark_delay() async throws {
        try XCTSkipIf(
            true,
            "Memory blows up because, after some time URLSessionTask.suspend doesn't stop network traffic"
        )
        try await testStreamingDownload(
            responseChunk: (1...1024 * 1024).map { _ in .random(in: (.min..<(.max))) }[...],
            numResponseChunks: 10_000,
            responseStreamWatermarks: (low: 10 * 1024 * 1024, high: 10 * 1024 * 1024),
            verification: .delay(.milliseconds(500))
        )
    }

    enum Verification {
        // Reconstruct the original chunks and verify they are what the server sent.
        case full
        // Just count the bytes received and verify the total matches what the server sent.
        case count
        // Add some artificial delay to simulate business logic to show how the backpressure mechanism works (or not).
        case delay(TimeAmount)
    }

    func testStreamingDownload(
        responseChunk: HTTPBody.ByteChunk,
        numResponseChunks: Int,
        responseStreamWatermarks: (low: Int, high: Int),
        verification: Verification
    ) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            let serverPort = try await AsyncTestHTTP1Server.start(connectionTaskGroup: &group) { connectionChannel in
                try await connectionChannel.executeThenClose { inbound, outbound in
                    for try await requestPart in inbound {
                        switch requestPart {
                        case .head:
                            try await outbound.write(
                                .head(
                                    .init(
                                        version: .http1_1,
                                        status: .ok,
                                        headers: ["Content-Type": "application/octet-stream"]
                                    )
                                )
                            )
                            print("Server sent response head")
                            for i in 1...numResponseChunks {
                                try await outbound.write(.body(ByteBuffer(bytes: responseChunk)))
                                print("Server sent body chunk \(i)/\(numResponseChunks) of \(responseChunk.count)")
                            }
                        case .body: preconditionFailure()
                        case .end:
                            try await outbound.write(.end(nil))
                            print("Server sent response end")
                        }
                    }
                }
            }
            print("Server running on 127.0.0.1:\(serverPort)")

            // Send the request.
            print("Client starting request")
            let (response, responseBody) = try await URLSession.shared.bidirectionalStreamingRequest(
                for: HTTPRequest(method: .get, scheme: nil, authority: nil, path: "/"),
                baseURL: URL(string: "http://127.0.0.1:\(serverPort)")!,
                requestBody: nil,
                requestStreamBufferSize: 16 * 1024 * 1024,
                responseStreamWatermarks: responseStreamWatermarks
            )
            print("Client received response head: \(response)")
            XCTAssertEqual(response.status, .ok)

            switch verification {
            case .full:
                // The response body will be chunked differently due to backpressure and URLSession's internal buffering.
                var unprocessedBytes = ByteBuffer()
                var numProcessedChunks = 0
                for try await receivedResponseChunk in responseBody! {
                    print("Client received some response body bytes (numBytes: \(receivedResponseChunk.count))")
                    unprocessedBytes.writeBytes(receivedResponseChunk)
                    while unprocessedBytes.readableBytes >= responseChunk.count {
                        print("Client reconstructing and verifying chunk \(numProcessedChunks+1)/\(numResponseChunks)")
                        XCTAssertEqual(
                            ArraySlice(unprocessedBytes.readBytes(length: responseChunk.count)!),
                            responseChunk
                        )
                        unprocessedBytes.discardReadBytes()
                        numProcessedChunks += 1
                    }
                }
                XCTAssertEqual(unprocessedBytes.readableBytes, 0)
                XCTAssertEqual(numProcessedChunks, numResponseChunks)
            case .count:
                var numBytesReceived = 0
                for try await receivedResponseChunk in responseBody! {
                    print("Client received some response body bytes (numBytes: \(receivedResponseChunk.count))")
                    numBytesReceived += receivedResponseChunk.count
                }
                XCTAssertEqual(numBytesReceived, responseChunk.count * numResponseChunks)
            case .delay(let delay):
                for try await receivedResponseChunk in responseBody! {
                    print("Client received some response body bytes (numBytes: \(receivedResponseChunk.count))")
                    print("Client doing fake work for \(delay)s")
                    try await Task.sleep(nanoseconds: UInt64(delay.nanoseconds))
                }
            }

            group.cancelAll()
        }
    }
}

#endif  // canImport(Darwin)
