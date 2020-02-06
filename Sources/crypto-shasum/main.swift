//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Foundation
import Crypto

let help = """
Usage: crypto-shasum [OPTION]... [FILE]...
Print SHA checksums.
With no FILE, or when FILE is -, read standard input.

  -a, --algorithm   256 (default), 384, 512
"""

enum SupportedHashFunction {
    case sha256
    case sha384
    case sha512

    init?(commandLineFlag flag: String) {
        switch flag {
        case "256":
            self = .sha256
        case "384":
            self = .sha384
        case "512":
            self = .sha512
        default:
            return nil
        }
    }

    func hashLoop(from input: FileHandle) -> Data {
        switch self {
        case .sha256:
            return Data(Self.hashLoop(from: input, with: SHA256.self))
        case .sha384:
            return Data(Self.hashLoop(from: input, with: SHA384.self))
        case .sha512:
            return Data(Self.hashLoop(from: input, with: SHA512.self))
        }
    }

    private static let readSize = 8192

    private static func hashLoop<HF: HashFunction>(from input: FileHandle, with hasher: HF.Type) -> HF.Digest {
        var hasher = HF()

        while true {
            let data = input.readData(ofLength: Self.readSize)
            if data.count == 0 {
                break
            }

            hasher.update(data: data)
        }

        return hasher.finalize()
    }
}


extension String {
    init(hexEncoding data: Data) {
        self = data.map { byte in
            let s = String(byte, radix: 16)
            switch s.count {
            case 0:
                return "00"
            case 1:
                return "0" + s
            case 2:
                return s
            default:
                fatalError("Weirdly hex encoded byte")
            }
        }.joined()
    }
}


func processInputs(_ handles: [String: FileHandle], algorithm: SupportedHashFunction) {
    for (name, fh) in handles {
        let result = algorithm.hashLoop(from: fh)
        print("\(String(hexEncoding: result))  \(name)")
    }
}

func main() {
    var arguments = CommandLine.arguments.dropFirst()
    var algorithm = SupportedHashFunction.sha256  // Default to sha256
    var files = [String: FileHandle]()

    // First get the flags.
    flagsLoop: while let first = arguments.first, first.starts(with: "-") {
        arguments = arguments.dropFirst()

        switch first {
        case "-a", "--algorithm":
            guard let flag = arguments.popFirst(), let newAlgorithm = SupportedHashFunction(commandLineFlag: flag) else {
                print("Unknown algorithm description.")
                return
            }
            algorithm = newAlgorithm

        case "--":
            break flagsLoop  // Everything left is files.

        case "-":
            // Whoops, this is a file. We need to read from stdin. Ignore any further flags, the rest of the arguments are files.
            files["-"] = FileHandle.standardInput
            break flagsLoop

        default:
            print(help)
            return
        }
    }

    // Now the files.
    while let first = arguments.popFirst() {
        // We assume this is a path.
        guard let fh = FileHandle(forReadingAtPath: first) else {
            print("Unable to open \(first)")
            return
        }

        files[first] = fh
    }

    if files.count == 0 {
        // No flags. We assume that means stdin.
        files["-"] = FileHandle.standardInput
    }

    processInputs(files, algorithm: algorithm)
}


main()
