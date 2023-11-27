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
import OpenAPIRuntime
import XCTest

func XCTAssertThrowsError<T>(
    _ expression: @autoclosure () async throws -> T,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line,
    _ errorHandler: (_ error: any Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("expression did not throw", file: file, line: line)
    } catch { errorHandler(error) }
}

func XCTSkipUnlessAsync(
    _ expression: @autoclosure () async throws -> Bool,
    _ message: @autoclosure () -> String? = nil,
    file: StaticString = #filePath,
    line: UInt = #line
) async throws {
    let result = try await expression()
    try XCTSkipUnless(result, message(), file: file, line: line)
}

func XCTUnwrapAsync<T>(
    _ expression: @autoclosure () async throws -> T?,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line
) async throws -> T {
    let maybeValue = try await expression()
    return try XCTUnwrap(maybeValue, message(), file: file, line: line)
}

func XCTAssertNilAsync(
    _ expression: @autoclosure () async throws -> Any?,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line
) async throws {
    let maybeValue = try await expression()
    XCTAssertNil(maybeValue, message(), file: file, line: line)
}

extension URL {
    var withoutPath: URL {
        var components = URLComponents(url: self, resolvingAgainstBaseURL: false)!
        components.path = ""
        return components.url!
    }
}

extension Collection {
    func chunks(of size: Int) -> [[Element]] {
        precondition(size > 0)
        var chunkStart = startIndex
        var results = [[Element]]()
        results.reserveCapacity((count - 1) / size + 1)
        while chunkStart < endIndex {
            let chunkEnd = index(chunkStart, offsetBy: size, limitedBy: endIndex) ?? endIndex
            results.append(Array(self[chunkStart..<chunkEnd]))
            chunkStart = chunkEnd
        }
        return results
    }
}

extension Stream.Event: CustomStringConvertible {
    // swift-format-ignore: AllPublicDeclarationsHaveDocumentation
    public var description: String {
        switch self {
        case .hasBytesAvailable: return "code=\(rawValue) (hasBytesAvailable)"
        case .hasSpaceAvailable: return "code=\(rawValue) (hasSpaceAvailable)"
        case .endEncountered: return "code=\(rawValue) (endEncountered)"
        case .errorOccurred: return "code=\(rawValue) (errorEncountered)"
        case .openCompleted: return "code=\(rawValue) (openCompleted)"
        default: return "code=\(rawValue) (unknown)"
        }
    }
}

extension Stream.Status: CustomStringConvertible {
    // swift-format-ignore: AllPublicDeclarationsHaveDocumentation
    public var description: String {
        switch self {
        case .notOpen: return "notOpen"
        case .opening: return "opening"
        case .open: return "open"
        case .reading: return "reading"
        case .writing: return "writing"
        case .atEnd: return "atEnd"
        case .closed: return "closed"
        case .error: return "error" #if canImport(Darwin)
        @unknown default: return "unknown"
        #endif
        }
    }
}

extension URLSessionTask.State: CustomDebugStringConvertible {
    // swift-format-ignore: AllPublicDeclarationsHaveDocumentation
    public var debugDescription: String {
        switch self {
        case .running: return "running"
        case .suspended: return "suspended"
        case .canceling: return "canelling"
        case .completed: return "completed" #if canImport(Darwin)
        @unknown default: return "unknown"
        #endif
        }
    }
}

class TestHelperTests: XCTestCase {
    func testArrayChunks() {
        for (array, chunkSize, expectedChunks) in [
            ([1, 2], 1, [[1], [2]]), ([1, 2, 3], 1, [[1], [2], [3]]), ([1, 2, 3], 2, [[1, 2], [3]]),
        ] { XCTAssertEqual(array.chunks(of: chunkSize), expectedChunks) }
    }
}

final class LockedValueBox<Value>: @unchecked Sendable where Value: Sendable {
    private let lock: NSLock = {
        let lock = NSLock()
        lock.name = "com.apple.swift-openapi-urlsession.lock.LockedValueBox"
        return lock
    }()
    private var value: Value
    init(_ value: Value) { self.value = value }
    func withValue<R>(_ work: (inout Value) throws -> R) rethrows -> R {
        lock.lock()
        defer { lock.unlock() }
        return try work(&value)
    }
}

extension AsyncSequence {
    /// Collect all elements in the sequence into an array.
    func collect() async throws -> [Element] {
        try await self.reduce(into: []) { accumulated, next in accumulated.append(next) }
    }
}
