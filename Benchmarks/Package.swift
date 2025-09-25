// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "swift-crypto-benchmarks",
    platforms: [.macOS("14")],
    dependencies: [
        .package(name: "swift-crypto", path: "../"),
        .package(url: "https://github.com/ordo-one/package-benchmark", from: "1.22.0"),
    ],
    targets: [
        .executableTarget(
            name: "SwiftCryptoBenchmarks",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "CryptoExtras", package: "swift-crypto"),
            ],
            path: "Benchmarks/",
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark")
            ]
        )
    ]
)
