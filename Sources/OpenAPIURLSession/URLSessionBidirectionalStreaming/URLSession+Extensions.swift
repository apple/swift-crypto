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

@available(macOS 12, iOS 15, tvOS 15, watchOS 8, *) extension URLSession {
    func bidirectionalStreamingRequest(
        for request: HTTPRequest,
        baseURL: URL,
        requestBody: HTTPBody?,
        requestStreamBufferSize: Int,
        responseStreamWatermarks: (low: Int, high: Int)
    ) async throws -> (HTTPResponse, HTTPBody?) {
        let urlRequest = try URLRequest(request, baseURL: baseURL)
        let task: URLSessionTask
        if requestBody != nil {
            task = uploadTask(withStreamedRequest: urlRequest)
        } else {
            task = dataTask(with: urlRequest)
        }
        return try await withTaskCancellationHandler {
            let delegate = BidirectionalStreamingURLSessionDelegate(
                requestBody: requestBody,
                requestStreamBufferSize: requestStreamBufferSize,
                responseStreamWatermarks: responseStreamWatermarks
            )
            let response = try await withCheckedThrowingContinuation { continuation in
                delegate.responseContinuation = continuation
                task.delegate = delegate
                task.resume()
            }
            let responseBody = HTTPBody(
                delegate.responseBodyStream,
                length: .init(from: response),
                iterationBehavior: .single
            )
            return (try HTTPResponse(response), responseBody)
        } onCancel: {
            task.cancel()
        }
    }
}

#endif  // canImport(Darwin)
