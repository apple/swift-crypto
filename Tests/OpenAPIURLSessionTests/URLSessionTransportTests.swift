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
import Foundation
#if !canImport(Darwin) && canImport(FoundationNetworking)
import FoundationNetworking
#endif
import HTTPTypes
import NIO
import NIOHTTP1
import OpenAPIRuntime
import XCTest
@testable import OpenAPIURLSession

// swift-format-ignore: AllPublicDeclarationsHaveDocumentation
class URLSessionTransportConverterTests: XCTestCase {
    static override func setUp() { OpenAPIURLSession.debugLoggingEnabled = false }

    func testRequestConversion() async throws {
        let request = HTTPRequest(
            method: .post,
            scheme: nil,
            authority: nil,
            path: "/hello%20world/Maria?greeting=Howdy",
            headerFields: [.init("x-mumble2")!: "mumble"]
        )
        let urlRequest = try URLRequest(request, baseURL: URL(string: "http://example.com/api")!)
        XCTAssertEqual(urlRequest.url, URL(string: "http://example.com/api/hello%20world/Maria?greeting=Howdy"))
        XCTAssertEqual(urlRequest.httpMethod, "POST")
        XCTAssertEqual(urlRequest.allHTTPHeaderFields?.count, 1)
        XCTAssertEqual(urlRequest.value(forHTTPHeaderField: "x-mumble2"), "mumble")
    }

    func testResponseConversion() async throws {
        let urlResponse: URLResponse = HTTPURLResponse(
            url: URL(string: "http://example.com/api/hello%20world/Maria?greeting=Howdy")!,
            statusCode: 201,
            httpVersion: "HTTP/1.1",
            headerFields: ["x-mumble3": "mumble"]
        )!
        let response = try HTTPResponse(urlResponse)
        XCTAssertEqual(response.status.code, 201)
        XCTAssertEqual(response.headerFields, [.init("x-mumble3")!: "mumble"])
    }
}

// swift-format-ignore: AllPublicDeclarationsHaveDocumentation
class URLSessionTransportBufferedTests: XCTestCase {
    var transport: (any ClientTransport)!

    static override func setUp() { OpenAPIURLSession.debugLoggingEnabled = false }

    override func setUp() async throws {
        transport = URLSessionTransport(configuration: .init(implementation: .buffering))
    }

    func testBasicGet() async throws { try await testHTTPBasicGet(transport: transport) }

    func testBasicPost() async throws { try await testHTTPBasicGet(transport: transport) }

    #if canImport(Darwin)  // Only passes on Darwin because Linux doesn't replay the request body on 307.
    func testHTTPRedirect_multipleIterationBehavior_succeeds() async throws {
        try await testHTTPRedirect(
            transport: transport,
            requestBodyIterationBehavior: .multiple,
            expectFailureDueToIterationBehavior: false
        )
    }

    func testHTTPRedirect_singleIterationBehavior_succeeds() async throws {
        try await testHTTPRedirect(
            transport: transport,
            requestBodyIterationBehavior: .single,
            expectFailureDueToIterationBehavior: false
        )
    }
    #endif
}

// swift-format-ignore: AllPublicDeclarationsHaveDocumentation
class URLSessionTransportStreamingTests: XCTestCase {
    var transport: (any ClientTransport)!

    static override func setUp() { OpenAPIURLSession.debugLoggingEnabled = false }

    override func setUpWithError() throws {
        try XCTSkipUnless(URLSessionTransport.Configuration.Implementation.platformSupportsStreaming)
        self.transport = URLSessionTransport(
            configuration: .init(
                implementation: .streaming(
                    requestBodyStreamBufferSize: 16 * 1024,
                    responseBodyStreamWatermarks: (low: 16 * 1024, high: 32 * 1024)
                )
            )
        )
    }

    func testBasicGet() async throws { try await testHTTPBasicGet(transport: transport) }

    func testBasicPost() async throws { try await testHTTPBasicGet(transport: transport) }

    #if canImport(Darwin)  // Only passes on Darwin because Linux doesn't replay the request body on 307.
    func testHTTPRedirect_multipleIterationBehavior_succeeds() async throws {
        try await testHTTPRedirect(
            transport: transport,
            requestBodyIterationBehavior: .multiple,
            expectFailureDueToIterationBehavior: false
        )
    }

    func testHTTPRedirect_singleIterationBehavior_fails() async throws {
        try await testHTTPRedirect(
            transport: transport,
            requestBodyIterationBehavior: .single,
            expectFailureDueToIterationBehavior: true
        )
    }
    #endif
}

class URLSessionTransportPlatformSupportTests: XCTestCase {
    func testDefaultsToStreamingIfSupported() {
        if URLSessionTransport.Configuration.Implementation.platformSupportsStreaming {
            guard case .streaming = URLSessionTransport.Configuration.Implementation.platformDefault else {
                XCTFail()
                return
            }
        } else {
            guard case .buffering = URLSessionTransport.Configuration.Implementation.platformDefault else {
                XCTFail()
                return
            }
        }
    }
}

func testHTTPRedirect(
    transport: any ClientTransport,
    requestBodyIterationBehavior: HTTPBody.IterationBehavior,
    expectFailureDueToIterationBehavior: Bool
) async throws {
    let requestBodyChunks = ["✊", "✊", " ", "knock", " ", "knock!"]
    let requestBody = HTTPBody(
        requestBodyChunks.async,
        length: .known(requestBodyChunks.joined().lengthOfBytes(using: .utf8)),
        iterationBehavior: requestBodyIterationBehavior
    )

    try await withThrowingTaskGroup(of: Void.self) { group in
        let serverPort = try await AsyncTestHTTP1Server.start(connectionTaskGroup: &group) { connectionChannel in
            try await connectionChannel.executeThenClose { inbound, outbound in
                var requestPartIterator = inbound.makeAsyncIterator()
                var currentURI: String? = nil
                var accumulatedBody = ByteBuffer()
                while let requestPart = try await requestPartIterator.next() {
                    switch requestPart {
                    case .head(let head):
                        debug("Server received head for \(head.uri)")
                        currentURI = head.uri
                    case .body(let buffer):
                        let currentURI = try XCTUnwrap(currentURI)
                        debug("Server received body bytes for \(currentURI) (numBytes: \(buffer.readableBytes))")
                        accumulatedBody.writeImmutableBuffer(buffer)
                    case .end:
                        let currentURI = try XCTUnwrap(currentURI)
                        debug("Server received end for \(currentURI)")
                        XCTAssertEqual(accumulatedBody, ByteBuffer(string: requestBodyChunks.joined()))
                        switch currentURI {
                        case "/old":
                            debug("Server reseting body buffer")
                            accumulatedBody = ByteBuffer()
                            try await outbound.write(
                                .head(
                                    .init(version: .http1_1, status: .temporaryRedirect, headers: ["Location": "/new"])
                                )
                            )
                            debug("Server sent head for \(currentURI)")
                            try await outbound.write(.end(nil))
                            debug("Server sent end for \(currentURI)")
                        case "/new":
                            try await outbound.write(.head(.init(version: .http1_1, status: .ok)))
                            debug("Server sent head for \(currentURI)")
                            try await outbound.write(.end(nil))
                            debug("Server sent end for \(currentURI)")
                        default: preconditionFailure()
                        }
                    }
                }
            }
        }
        debug("Server running on 127.0.0.1:\(serverPort)")

        // Send the request.
        debug("Client starting request")
        if expectFailureDueToIterationBehavior {
            await XCTAssertThrowsError(
                try await transport.send(
                    HTTPRequest(method: .post, scheme: nil, authority: nil, path: "/old"),
                    body: requestBody,
                    baseURL: URL(string: "http://127.0.0.1:\(serverPort)")!,
                    operationID: "unused"
                )
            ) { error in XCTAssertEqual((error as? URLError)?.code, .cancelled, "Unexpected error: \(error)") }
        } else {
            let (response, _) = try await transport.send(
                HTTPRequest(method: .post, scheme: nil, authority: nil, path: "/old"),
                body: requestBody,
                baseURL: URL(string: "http://127.0.0.1:\(serverPort)")!,
                operationID: "unused"
            )
            debug("Client received response head: \(response)")
            XCTAssertEqual(response.status, .ok)
        }

        group.cancelAll()
    }
}

func testHTTPBasicGet(transport: any ClientTransport) async throws {
    let requestPath = "/hello/world"
    let responseBodyMessage = "Hey!"

    try await withThrowingTaskGroup(of: Void.self) { group in
        let serverPort = try await AsyncTestHTTP1Server.start(connectionTaskGroup: &group) { connectionChannel in
            try await connectionChannel.executeThenClose { inbound, outbound in
                var requestPartIterator = inbound.makeAsyncIterator()
                while let requestPart = try await requestPartIterator.next() {
                    switch requestPart {
                    case .head(let head):
                        XCTAssertEqual(head.uri, requestPath)
                        XCTAssertEqual(head.method, .GET)
                    case .body: XCTFail("Didn't expect any request body bytes.")
                    case .end:
                        try await outbound.write(.head(.init(version: .http1_1, status: .ok)))
                        try await outbound.write(.body(ByteBuffer(string: responseBodyMessage)))
                        try await outbound.write(.end(nil))
                    }
                }
            }
        }
        debug("Server running on 127.0.0.1:\(serverPort)")

        // Send the request.
        debug("Client starting request")
        let (response, maybeResponseBody) = try await transport.send(
            HTTPRequest(method: .get, scheme: nil, authority: nil, path: requestPath),
            body: nil,
            baseURL: URL(string: "http://127.0.0.1:\(serverPort)")!,
            operationID: "unused"
        )
        debug("Client received response head: \(response)")
        XCTAssertEqual(response.status, .ok)
        let receivedMessage = try await String(collecting: try XCTUnwrap(maybeResponseBody), upTo: .max)
        XCTAssertEqual(receivedMessage, responseBodyMessage)

        group.cancelAll()
    }
}

func testHTTPBasicPost(transport: any ClientTransport) async throws {
    let requestPath = "/hello/world"
    let requestBodyMessage = "Hello, world!"
    let responseBodyMessage = "Hey!"

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
                        XCTAssertEqual(accumulatedBody, ByteBuffer(string: requestBodyMessage))
                        try await outbound.write(.head(.init(version: .http1_1, status: .ok)))
                        try await outbound.write(.body(ByteBuffer(string: responseBodyMessage)))
                        try await outbound.write(.end(nil))
                    }
                }
            }
        }
        debug("Server running on 127.0.0.1:\(serverPort)")

        // Send the request.
        debug("Client starting request")
        let (response, maybeResponseBody) = try await transport.send(
            HTTPRequest(method: .post, scheme: nil, authority: nil, path: requestPath),
            body: HTTPBody(requestBodyMessage),
            baseURL: URL(string: "http://127.0.0.1:\(serverPort)")!,
            operationID: "unused"
        )
        debug("Client received response head: \(response)")
        XCTAssertEqual(response.status, .ok)
        let receivedMessage = try await String(collecting: try XCTUnwrap(maybeResponseBody), upTo: .max)
        XCTAssertEqual(receivedMessage, responseBodyMessage)

        group.cancelAll()
    }
}

class URLSessionTransportDebugLoggingTests: XCTestCase {
    func testDebugLoggingEnabled() {
        let expectation = expectation(description: "message autoclosure evaluated")
        func message() -> String {
            expectation.fulfill()
            return "message"
        }
        OpenAPIURLSession.debugLoggingEnabled = true
        debug(message())
        wait(for: [expectation], timeout: 0)
    }

    func testDebugLoggingDisabled() {
        let expectation = expectation(description: "message autoclosure evaluated")
        expectation.isInverted = true
        func message() -> String {
            expectation.fulfill()
            return "message"
        }
        OpenAPIURLSession.debugLoggingEnabled = false
        debug(message())
        wait(for: [expectation], timeout: 0)
    }
}
