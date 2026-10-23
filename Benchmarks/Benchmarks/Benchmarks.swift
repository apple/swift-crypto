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
import CryptoExtras

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

let benchmarks: @Sendable () -> Void = {
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

    Benchmark(
        "key-exchange-p256",
        configuration: Benchmark.Configuration(
            metrics: defaultMetrics,
            scalingFactor: .kilo,
            maxDuration: .seconds(10_000_000),
            maxIterations: 10
        )
    ) { benchmark in
        for _ in benchmark.scaledIterations {
            let (key1, key2) = (P256.KeyAgreement.PrivateKey(), P256.KeyAgreement.PrivateKey())
            blackHole(try key1.sharedSecretFromKeyAgreement(with: key2.publicKey))
        }
    }

    Benchmark(
        "key-exchange-p384",
        configuration: Benchmark.Configuration(
            metrics: defaultMetrics,
            scalingFactor: .kilo,
            maxDuration: .seconds(10_000_000),
            maxIterations: 10
        )
    ) { benchmark in
        for _ in benchmark.scaledIterations {
            let (key1, key2) = (P384.KeyAgreement.PrivateKey(), P384.KeyAgreement.PrivateKey())
            blackHole(try key1.sharedSecretFromKeyAgreement(with: key2.publicKey))
        }
    }

    Benchmark(
        "key-exchange-p521",
        configuration: Benchmark.Configuration(
            metrics: defaultMetrics,
            scalingFactor: .kilo,
            maxDuration: .seconds(10_000_000),
            maxIterations: 10
        )
    ) { benchmark in
        for _ in benchmark.scaledIterations {
            let (key1, key2) = (P521.KeyAgreement.PrivateKey(), P521.KeyAgreement.PrivateKey())
            blackHole(try key1.sharedSecretFromKeyAgreement(with: key2.publicKey))
        }
    }

    Benchmark(
        "hmac-sha256-authenticate",
        configuration: Benchmark.Configuration(
            metrics: defaultMetrics,
            scalingFactor: .mega,
            maxDuration: .seconds(10_000_000),
            maxIterations: 5
        )
    ) { benchmark in
        let key = SymmetricKey(size: .bits256)
        let message = Data(repeating: 0x41, count: 1024)

        benchmark.startMeasurement()

        for _ in benchmark.scaledIterations {
            blackHole(HMAC<SHA256>.authenticationCode(for: message, using: key))
        }
    }

    Benchmark(
        "hkdf-sha256-derive",
        configuration: Benchmark.Configuration(
            metrics: defaultMetrics,
            scalingFactor: .kilo,
            maxDuration: .seconds(10_000_000),
            maxIterations: 10
        )
    ) { benchmark in
        let inputKeyMaterial = SymmetricKey(size: .bits256)
        let salt = Data("benchmark salt".utf8)
        let info = Data("benchmark info".utf8)

        benchmark.startMeasurement()

        for _ in benchmark.scaledIterations {
            blackHole(
                HKDF<SHA256>.deriveKey(
                    inputKeyMaterial: inputKeyMaterial,
                    salt: salt,
                    info: info,
                    outputByteCount: 1024
                )
            )
        }
    }

    Benchmark(
        "aes-keywrap-unwrap",
        configuration: Benchmark.Configuration(
            metrics: defaultMetrics,
            scalingFactor: .mega,
            maxDuration: .seconds(10_000_000),
            maxIterations: 5
        )
    ) { benchmark in
        let kek = SymmetricKey(size: .bits256)
        let wrapped = try AES.KeyWrap.wrap(SymmetricKey(size: .bits256), using: kek)

        benchmark.startMeasurement()

        for _ in benchmark.scaledIterations {
            blackHole(try AES.KeyWrap.unwrap(wrapped, using: kek))
        }
    }

    if #available(macOS 26.0, *) {
        Benchmark(
            "mlkem768-decapsulate",
            configuration: Benchmark.Configuration(
                metrics: defaultMetrics,
                scalingFactor: .kilo,
                maxDuration: .seconds(10_000_000),
                maxIterations: 10
            )
        ) { benchmark in
            let privateKey = try MLKEM768.PrivateKey()
            let encapsulated = try privateKey.publicKey.encapsulate().encapsulated

            benchmark.startMeasurement()

            for _ in benchmark.scaledIterations {
                blackHole(try privateKey.decapsulate(encapsulated))
            }
        }
    }

    Benchmark(
        "pbkdf2-sha256-derive",
        configuration: Benchmark.Configuration(
            metrics: defaultMetrics,
            scalingFactor: .kilo,
            maxDuration: .seconds(10_000_000),
            maxIterations: 10
        )
    ) { benchmark in
        let password = Data("benchmark password".utf8)
        let salt = Data("benchmark salt".utf8)

        benchmark.startMeasurement()

        for _ in benchmark.scaledIterations {
            blackHole(
                try KDF.Insecure.PBKDF2.deriveKey(
                    from: password,
                    salt: salt,
                    using: .sha256,
                    outputByteCount: 32,
                    unsafeUncheckedRounds: 1_000
                )
            )
        }
    }

    Benchmark(
        "scrypt-derive",
        configuration: Benchmark.Configuration(
            metrics: defaultMetrics,
            scalingFactor: .kilo,
            maxDuration: .seconds(10_000_000),
            maxIterations: 3
        )
    ) { benchmark in
        let password = Data("benchmark password".utf8)
        let salt = Data("benchmark salt".utf8)

        benchmark.startMeasurement()

        for _ in benchmark.scaledIterations {
            blackHole(
                try KDF.Scrypt.deriveKey(
                    from: password,
                    salt: salt,
                    outputByteCount: 32,
                    rounds: 1 << 10,
                    blockSize: 8,
                    parallelism: 1
                )
            )
        }
    }
}
