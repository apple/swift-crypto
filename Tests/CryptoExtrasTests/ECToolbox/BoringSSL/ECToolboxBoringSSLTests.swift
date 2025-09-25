//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Crypto
import Foundation
import XCTest

#if !canImport(Darwin) || canImport(CryptoKit, _version: 241.100.42)
// Corresponds to the CryptoKit in XCode 16.3, which has Sendable annotations
import Crypto
@testable import CryptoExtras
#else
@preconcurrency import Crypto
@testable import CryptoExtras
#endif

final class ECToolboxBoringSSLTests: XCTestCase {
    func testThreadLocalFFAC() async {
        await testThreadLocalFFAC(P256.self)
        await testThreadLocalFFAC(P384.self)
        await testThreadLocalFFAC(P521.self)
    }

    func testThreadLocalFFAC(_ Curve: (some OpenSSLSupportedNISTCurve & Sendable).Type) async {
        let numThreads = 3
        let numReadsPerThread = 2

        var threads:
            [(
                thread: Thread,
                thisThreadDidReads: XCTestExpectation,
                allThreadsDidReads: XCTestExpectation,
                thisThreadFinished: XCTestExpectation
            )] = []

        let objectIdentifiers: LockedBox<[(threadID: Int, ffacID: ObjectIdentifier)]> = .init(initialValue: [])

        for i in 1...numThreads {
            let thisThreadDidReads = expectation(description: "this thread did its reads")
            let allThreadsDidReads = expectation(description: "all threads did their reads")
            let thisThreadFinished = expectation(description: "this thread is finished")
            let thread = Thread {
                for _ in 1...numReadsPerThread {
                    objectIdentifiers.withLockedValue {
                        $0.append((i, ObjectIdentifier(Curve.__ffac)))
                    }
                }
                thisThreadDidReads.fulfill()
                XCTWaiter().wait(for: [allThreadsDidReads], timeout: .greatestFiniteMagnitude)
                thisThreadFinished.fulfill()
            }
            thread.name = "thread-\(i)"
            threads.append((thread, thisThreadDidReads, allThreadsDidReads, thisThreadFinished))
            thread.start()
        }
        await fulfillment(of: threads.map(\.thisThreadDidReads), timeout: 0.5)
        for thread in threads { thread.allThreadsDidReads.fulfill() }
        await fulfillment(of: threads.map(\.thisThreadFinished), timeout: 0.5)

        objectIdentifiers.withLockedValue { objectIdentifiers in
            XCTAssertEqual(objectIdentifiers.count, numThreads * numReadsPerThread)
            for threadID in 1...numThreads {
                let partitionBoundary = objectIdentifiers.partition(by: { $0.threadID == threadID })
                let otherThreadsObjIDs = objectIdentifiers[..<partitionBoundary].map(\.ffacID)
                let thisThreadObjIDs = objectIdentifiers[partitionBoundary...].map(\.ffacID)
                let intersection = Set(thisThreadObjIDs).intersection(Set(otherThreadsObjIDs))
                XCTAssertEqual(
                    thisThreadObjIDs.count,
                    numReadsPerThread,
                    "Thread should read \(numReadsPerThread) times."
                )
                XCTAssertEqual(Set(thisThreadObjIDs).count, 1, "Thread should see same object on every read.")
                XCTAssert(intersection.isEmpty, "Thread should see different objects from other threads.")
            }
        }
    }
}

final class LockedBox<Value: Sendable>: @unchecked Sendable {
    private let lock: NSLock
    private var value: Value

    init(initialValue: Value) {
        self.value = initialValue
        self.lock = NSLock()
    }

    func withLockedValue<ReturnType>(_ body: (inout Value) throws -> ReturnType) rethrows -> ReturnType {
        self.lock.lock()
        defer {
            self.lock.unlock()
        }
        return try body(&self.value)
    }
}
