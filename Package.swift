// swift-tools-version: 5.8
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
import PackageDescription

// General Swift-settings for all targets.
var swiftSettings: [SwiftSetting] = []

#if swift(>=5.9)
swiftSettings.append(
    // https://github.com/apple/swift-evolution/blob/main/proposals/0335-existential-any.md
    // Require `any` for existential types.
    .enableUpcomingFeature("ExistentialAny")
)
#endif

let package = Package(
    name: "swift-openapi-urlsession",
    platforms: [
        .macOS(.v10_15), .iOS(.v13), .tvOS(.v13), .watchOS(.v6),
    ],
    products: [
        .library(
            name: "OpenAPIURLSession",
            targets: ["OpenAPIURLSession"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-openapi-runtime", .upToNextMinor(from: "0.3.0")),
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "OpenAPIURLSession",
            dependencies: [
                .product(name: "OpenAPIRuntime", package: "swift-openapi-runtime"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "OpenAPIURLSessionTests",
            dependencies: ["OpenAPIURLSession"],
            swiftSettings: swiftSettings
        ),
    ]
)
