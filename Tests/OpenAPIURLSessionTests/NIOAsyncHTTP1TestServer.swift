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
import NIOCore
import NIOPosix
import NIOHTTP1

final class AsyncTestHTTP1Server {

    typealias ConnectionHandler = @Sendable (NIOAsyncChannel<HTTPServerRequestPart, HTTPServerByteBufferResponsePart>)
        async throws -> Void

    /// Use `start(host:port:connectionHandler:)` instead.
    private init() {}

    /// Start a localhost HTTP1 server with a given connection handler.
    ///
    /// - Parameters:
    ///   - connectionTaskGroup: Task group used to run the connection handler on new connections.
    ///   - connectionHandler: Handler to run for each new connection.
    /// - Returns: The port on which the server is running.
    /// - Throws: If there was an error starting the server.
    static func start(
        connectionTaskGroup: inout ThrowingTaskGroup<Void, any Error>,
        connectionHandler: @escaping ConnectionHandler
    ) async throws -> Int {
        let group: MultiThreadedEventLoopGroup = .singleton
        let channel = try await ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .bind(host: "127.0.0.1", port: 0) { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.configureHTTPServerPipeline()
                    try channel.pipeline.syncOperations.addHandler(HTTPByteBufferResponseChannelHandler())
                    return try NIOAsyncChannel(
                        wrappingChannelSynchronously: channel,
                        configuration: NIOAsyncChannel.Configuration(
                            inboundType: HTTPServerRequestPart.self,
                            outboundType: HTTPServerByteBufferResponsePart.self
                        )
                    )
                }
            }

        connectionTaskGroup.addTask {
            // NOTE: it would be better to use `withThrowingDiscardingTaskGroup` here, but this would require some availablity dance and this is just used in tests.
            try await withThrowingTaskGroup(of: Void.self) { group in
                try await channel.executeThenClose { inbound, outbound in
                    for try await connectionChannel in inbound {
                        group.addTask {
                            do {
                                print("Sevrer handling new connection")
                                try await connectionHandler(connectionChannel)
                                print("Server done handling connection")
                            } catch { print("Server error handling connection: \(error)") }
                        }
                    }
                }
            }
        }
        return channel.channel.localAddress!.port!
    }
}

/// Because `HTTPServerResponsePart` is not sendable because its body type is `IOData`, which is an abstraction over a
/// `ByteBuffer` or `FileRegion`. The latter is not sendable, so we need a channel handler that deals in terms of only
/// `ByteBuffer`.
extension AsyncTestHTTP1Server {
    typealias HTTPServerByteBufferResponsePart = HTTPPart<HTTPResponseHead, ByteBuffer>

    final class HTTPByteBufferResponseChannelHandler: ChannelOutboundHandler, RemovableChannelHandler {
        typealias OutboundIn = HTTPServerByteBufferResponsePart
        typealias OutboundOut = HTTPServerResponsePart

        func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
            let part = unwrapOutboundIn(data)
            switch part {
            case .head(let head): context.write(self.wrapOutboundOut(.head(head)), promise: promise)
            case .body(let buffer): context.write(self.wrapOutboundOut(.body(.byteBuffer(buffer))), promise: promise)
            case .end(let headers): context.write(self.wrapOutboundOut(.end(headers)), promise: promise)
            }
        }
    }

}
