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
import OpenAPIRuntime
import XCTest
@testable import OpenAPIURLSession

enum CancellationPoint: CaseIterable {
    case beforeSendingHead
    case beforeSendingRequestBody
    case partwayThroughSendingRequestBody
    case beforeConsumingResponseBody
    case partwayThroughConsumingResponseBody
    case afterConsumingResponseBody
}

func testTaskCancelled(_ cancellationPoint: CancellationPoint, transport: URLSessionTransport) async throws {
    let requestPath = "/hello/world"
    let requestBodyElements = ["Hello,", "world!"]
    let requestBodySequence = MockAsyncSequence(elementsToVend: requestBodyElements, gatingProduction: true)
    let requestBody = HTTPBody(
        requestBodySequence,
        length: .known(Int64(requestBodyElements.joined().lengthOfBytes(using: .utf8))),
        iterationBehavior: .single
    )

    let responseBodyMessage = "Hey!"

    let taskShouldCancel = XCTestExpectation(description: "Concurrency task cancelled")
    let taskCancelled = XCTestExpectation(description: "Concurrency task cancelled")

    try await withThrowingTaskGroup(of: Void.self) { group in
        let serverPort = try await AsyncTestHTTP1Server.start(connectionTaskGroup: &group) { connectionChannel in
            try await connectionChannel.executeThenClose { inbound, outbound in
                var requestPartIterator = inbound.makeAsyncIterator()
                var accumulatedBody = ByteBuffer()
                while let requestPart = try await requestPartIterator.next() {
                    switch requestPart {
                    case .head(let head):
                        XCTAssertEqual(head.uri, requestPath)
                        XCTAssertEqual(head.method, .POST)
                    case .body(let buffer): accumulatedBody.writeImmutableBuffer(buffer)
                    case .end:
                        switch cancellationPoint {
                        case .beforeConsumingResponseBody, .partwayThroughConsumingResponseBody,
                            .afterConsumingResponseBody:
                            XCTAssertEqual(
                                String(decoding: accumulatedBody.readableBytesView, as: UTF8.self),
                                requestBodyElements.joined()
                            )
                        case .beforeSendingHead, .beforeSendingRequestBody, .partwayThroughSendingRequestBody: break
                        }
                        try await outbound.write(.head(.init(version: .http1_1, status: .ok)))
                        try await outbound.write(.body(ByteBuffer(string: responseBodyMessage)))
                        try await outbound.write(.end(nil))
                    }
                }
            }
        }
        debug("Server running on 127.0.0.1:\(serverPort)")

        let task = Task {
            if case .beforeSendingHead = cancellationPoint {
                taskShouldCancel.fulfill()
                await fulfillment(of: [taskCancelled])
            }
            debug("Client starting request")
            async let (asyncResponse, asyncResponseBody) = try await transport.send(
                HTTPRequest(method: .post, scheme: nil, authority: nil, path: requestPath),
                body: requestBody,
                baseURL: URL(string: "http://127.0.0.1:\(serverPort)")!,
                operationID: "unused"
            )

            if case .beforeSendingRequestBody = cancellationPoint {
                taskShouldCancel.fulfill()
                await fulfillment(of: [taskCancelled])
            }

            requestBodySequence.openGate(for: 1)

            if case .partwayThroughSendingRequestBody = cancellationPoint {
                taskShouldCancel.fulfill()
                await fulfillment(of: [taskCancelled])
            }

            requestBodySequence.openGate()

            let (response, maybeResponseBody) = try await (asyncResponse, asyncResponseBody)

            debug("Client received response head: \(response)")
            XCTAssertEqual(response.status, .ok)
            let responseBody = try XCTUnwrap(maybeResponseBody)

            if case .beforeConsumingResponseBody = cancellationPoint {
                taskShouldCancel.fulfill()
                await fulfillment(of: [taskCancelled])
            }

            var iterator = responseBody.makeAsyncIterator()

            _ = try await iterator.next()

            if case .partwayThroughConsumingResponseBody = cancellationPoint {
                taskShouldCancel.fulfill()
                await fulfillment(of: [taskCancelled])
            }

            while try await iterator.next() != nil {

            }

            if case .afterConsumingResponseBody = cancellationPoint {
                taskShouldCancel.fulfill()
                await fulfillment(of: [taskCancelled])
            }

        }

        await fulfillment(of: [taskShouldCancel])
        task.cancel()
        taskCancelled.fulfill()

        switch transport.configuration.implementation {
        case .buffering:
            switch cancellationPoint {
            case .beforeSendingHead, .beforeSendingRequestBody, .partwayThroughSendingRequestBody:
                await XCTAssertThrowsError(try await task.value) { error in XCTAssertTrue(error is CancellationError) }
            case .beforeConsumingResponseBody, .partwayThroughConsumingResponseBody, .afterConsumingResponseBody:
                try await task.value
            }
        case .streaming:
            switch cancellationPoint {
            case .beforeSendingHead:
                await XCTAssertThrowsError(try await task.value) { error in XCTAssertTrue(error is CancellationError) }
            case .beforeSendingRequestBody, .partwayThroughSendingRequestBody:
                await XCTAssertThrowsError(try await task.value) { error in
                    guard let urlError = error as? URLError else {
                        XCTFail()
                        return
                    }
                    XCTAssertEqual(urlError.code, .cancelled)
                }
            case .beforeConsumingResponseBody, .partwayThroughConsumingResponseBody, .afterConsumingResponseBody:
                try await task.value
            }
        }

        group.cancelAll()
    }

}

func fulfillment(
    of expectations: [XCTestExpectation],
    timeout seconds: TimeInterval = .infinity,
    enforceOrder enforceOrderOfFulfillment: Bool = false,
    file: StaticString = #file,
    line: UInt = #line
) async {
    guard
        case .completed = await XCTWaiter.fulfillment(
            of: expectations,
            timeout: seconds,
            enforceOrder: enforceOrderOfFulfillment
        )
    else {
        XCTFail("Expectation was not fulfilled", file: file, line: line)
        return
    }
}

extension URLSessionTransportBufferedTests {
    func testCancellation_beforeSendingHead() async throws {
        try await testTaskCancelled(.beforeSendingHead, transport: transport)
    }

    func testCancellation_beforeSendingRequestBody() async throws {
        try await testTaskCancelled(.beforeSendingRequestBody, transport: transport)
    }

    func testCancellation_partwayThroughSendingRequestBody() async throws {
        try await testTaskCancelled(.partwayThroughSendingRequestBody, transport: transport)
    }

    func testCancellation_beforeConsumingResponseBody() async throws {
        try await testTaskCancelled(.beforeConsumingResponseBody, transport: transport)
    }

    func testCancellation_partwayThroughConsumingResponseBody() async throws {
        try await testTaskCancelled(.partwayThroughConsumingResponseBody, transport: transport)
    }

    func testCancellation_afterConsumingResponseBody() async throws {
        try await testTaskCancelled(.afterConsumingResponseBody, transport: transport)
    }
}

extension URLSessionTransportStreamingTests {
    func testCancellation_beforeSendingHead() async throws {
        try await testTaskCancelled(.beforeSendingHead, transport: transport)
    }

    func testCancellation_beforeSendingRequestBody() async throws {
        try await testTaskCancelled(.beforeSendingRequestBody, transport: transport)
    }

    func testCancellation_partwayThroughSendingRequestBody() async throws {
        try await testTaskCancelled(.partwayThroughSendingRequestBody, transport: transport)
    }

    func testCancellation_beforeConsumingResponseBody() async throws {
        try await testTaskCancelled(.beforeConsumingResponseBody, transport: transport)
    }

    func testCancellation_partwayThroughConsumingResponseBody() async throws {
        try await testTaskCancelled(.partwayThroughConsumingResponseBody, transport: transport)
    }

    func testCancellation_afterConsumingResponseBody() async throws {
        try await testTaskCancelled(.afterConsumingResponseBody, transport: transport)
    }
}

#endif  // canImport(Darwin)
