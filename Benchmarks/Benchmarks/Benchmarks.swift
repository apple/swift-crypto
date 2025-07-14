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
import Benchmark
import Crypto
import Foundation
import _CryptoExtras

let benchmarks = {
    let defaultMetrics: [BenchmarkMetric] = [.mallocCountTotal, .cpuTotal]

    Benchmark(
        "arc-issue-p256",
        configuration: Benchmark.Configuration(
            metrics: defaultMetrics,
            scalingFactor: .kilo,
            maxDuration: .seconds(10_000_000),
            maxIterations: 3
        )
    ) { benchmark in
        let privateKey = P256._ARCV1.PrivateKey()
        let publicKey = privateKey.publicKey
        let requestContext = Data("shared request context".utf8)
        let precredential = try publicKey.prepareCredentialRequest(requestContext: requestContext)
        let credentialRequest = precredential.credentialRequest

        benchmark.startMeasurement()

        for _ in benchmark.scaledIterations {
            blackHole(try privateKey.issue(credentialRequest))
        }
    }

    Benchmark(
        "arc-verify-p256",
        configuration: Benchmark.Configuration(
            metrics: defaultMetrics,
            scalingFactor: .kilo,
            maxDuration: .seconds(10_000_000),
            maxIterations: 10
        )
    ) { benchmark in
        let privateKey = P256._ARCV1.PrivateKey()
        let publicKey = privateKey.publicKey
        let requestContext = Data("shared request context".utf8)
        let (presentationContext, presentationLimit) = (Data("shared presentation context".utf8), 2)
        let precredential = try publicKey.prepareCredentialRequest(requestContext: requestContext)
        let credentialRequest = precredential.credentialRequest
        let credentialResponse = try privateKey.issue(credentialRequest)
        var credential = try publicKey.finalize(credentialResponse, for: precredential)
        let (presentation, nonce) = try credential.makePresentation(
            context: presentationContext,
            presentationLimit: presentationLimit
        )

        benchmark.startMeasurement()

        for _ in benchmark.scaledIterations {
            blackHole(
                try privateKey.verify(
                    presentation,
                    requestContext: requestContext,
                    presentationContext: presentationContext,
                    presentationLimit: presentationLimit,
                    nonce: nonce
                )
            )
        }
    }

    Benchmark(
        "arc-issue-p384",
        configuration: Benchmark.Configuration(
            metrics: defaultMetrics,
            scalingFactor: .kilo,
            maxDuration: .seconds(10_000_000),
            maxIterations: 3
        )
    ) { benchmark in
        let privateKey = P384._ARCV1.PrivateKey()
        let publicKey = privateKey.publicKey
        let requestContext = Data("shared request context".utf8)
        let precredential = try publicKey.prepareCredentialRequest(requestContext: requestContext)
        let credentialRequest = precredential.credentialRequest

        benchmark.startMeasurement()

        for _ in benchmark.scaledIterations {
            blackHole(try privateKey.issue(credentialRequest))
        }
    }

    Benchmark(
        "arc-verify-p384",
        configuration: Benchmark.Configuration(
            metrics: defaultMetrics,
            scalingFactor: .kilo,
            maxDuration: .seconds(10_000_000),
            maxIterations: 10
        )
    ) { benchmark in
        let privateKey = P384._ARCV1.PrivateKey()
        let publicKey = privateKey.publicKey
        let requestContext = Data("shared request context".utf8)
        let (presentationContext, presentationLimit) = (Data("shared presentation context".utf8), 2)
        let precredential = try publicKey.prepareCredentialRequest(requestContext: requestContext)
        let credentialRequest = precredential.credentialRequest
        let credentialResponse = try privateKey.issue(credentialRequest)
        var credential = try publicKey.finalize(credentialResponse, for: precredential)
        let (presentation, nonce) = try credential.makePresentation(
            context: presentationContext,
            presentationLimit: presentationLimit
        )

        benchmark.startMeasurement()

        for _ in benchmark.scaledIterations {
            blackHole(
                try privateKey.verify(
                    presentation,
                    requestContext: requestContext,
                    presentationContext: presentationContext,
                    presentationLimit: presentationLimit,
                    nonce: nonce
                )
            )
        }
    }

    Benchmark(
        "voprf-evaluate-p384",
        configuration: Benchmark.Configuration(
            metrics: defaultMetrics,
            scalingFactor: .kilo,
            maxDuration: .seconds(10_000_000),
            maxIterations: 3
        )
    ) { benchmark in
        let privateKey = P384._VOPRF.PrivateKey()
        let publicKey = privateKey.publicKey
        let privateInput = Data("This is some input data".utf8)
        let blindedInput = try publicKey.blind(privateInput)
        let blindedElement = blindedInput.blindedElement

        benchmark.startMeasurement()

        for _ in benchmark.scaledIterations {
            blackHole(try privateKey.evaluate(blindedElement))
        }
    }
}
