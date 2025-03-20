// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CryptoKeyUtils",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "CryptoKeyUtils",
            targets: ["CryptoKeyUtils"]),
    ],
    dependencies: [
        .package(url: "https://github.com/tomieq/SwiftExtensions", branch: "master")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "CryptoKeyUtils",
            dependencies: [
                .product(name: "SwiftExtensions", package: "SwiftExtensions")
            ]),
        .testTarget(
            name: "CryptoKeyUtilsTests",
            dependencies: ["CryptoKeyUtils"]
        ),
    ]
)
