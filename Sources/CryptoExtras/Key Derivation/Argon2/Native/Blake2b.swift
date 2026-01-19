//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Foundation
import Crypto

internal enum Blake2b {
    static let blockBytes = 128
    static let outBytes = 64
    static let iv: [UInt64] = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
    static let sigma: [[Int]] = [
        [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ], [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
        [11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ], [ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
        [ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ], [ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
        [12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ], [13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
        [ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ], [10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 ],
        [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ], [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ]
    ]

    static func hash<D: DataProtocol>(data: D, outLength: Int) -> Data {
        var h = iv; h[0] ^= UInt64(0x01010000) ^ UInt64(outLength); let buffer = [UInt8](data)
        let blockCount = buffer.count == 0 ? 1 : (buffer.count + blockBytes - 1) / blockBytes
        var t: UInt64 = 0
        for i in 0..<blockCount {
            let isLast = i == blockCount - 1; var block = [UInt64](repeating: 0, count: 16); let start = i * blockBytes
            let end = min(start + blockBytes, buffer.count); let len = end - start; t += UInt64(len)
            for j in 0..<16 {
                let offset = j * 8; var val: UInt64 = 0
                for k in 0..<8 { let idx = start + offset + k; if idx < buffer.count { val |= UInt64(buffer[idx]) << (k * 8) } }
                block[j] = val
            }
            compress(h: &h, m: block, t: t, f: isLast)
        }
        var result = Data()
        for i in 0..<((outLength + 7) / 8) {
            var val = h[i]; for _ in 0..<min(8, outLength - i * 8) { result.append(UInt8(val & 0xff)); val >>= 8 }
        }
        return result
    }

    private static func compress(h: inout [UInt64], m: [UInt64], t: UInt64, f: Bool) {
        var v = [UInt64](repeating: 0, count: 16); for i in 0..<8 { v[i] = h[i]; v[i + 8] = iv[i] }
        v[12] ^= t; if f { v[14] ^= 0xffffffffffffffff }
        for i in 0..<12 {
            let row = sigma[i]
            mixStep(v: &v, a: 0, b: 4, c: 8, d: 12, x: m[row[0]], y: m[row[1]])
            mixStep(v: &v, a: 1, b: 5, c: 9, d: 13, x: m[row[2]], y: m[row[3]])
            mixStep(v: &v, a: 2, b: 6, c: 10, d: 14, x: m[row[4]], y: m[row[5]])
            mixStep(v: &v, a: 3, b: 7, c: 11, d: 15, x: m[row[6]], y: m[row[7]])
            mixStep(v: &v, a: 0, b: 5, c: 10, d: 15, x: m[row[8]], y: m[row[9]])
            mixStep(v: &v, a: 1, b: 6, c: 11, d: 12, x: m[row[10]], y: m[row[11]])
            mixStep(v: &v, a: 2, b: 7, c: 8, d: 13, x: m[row[12]], y: m[row[13]])
            mixStep(v: &v, a: 3, b: 4, c: 9, d: 14, x: m[row[14]], y: m[row[15]])
        }
        for i in 0..<8 { h[i] ^= v[i] ^ v[i + 8] }
    }

    private static func mixStep(v: inout [UInt64], a: Int, b: Int, c: Int, d: Int, x: UInt64, y: UInt64) {
        v[a] = v[a] &+ v[b] &+ x; v[d] = rotateRight(v[d] ^ v[a], by: 32); v[c] = v[c] &+ v[d]; v[b] = rotateRight(v[b] ^ v[c], by: 24)
        v[a] = v[a] &+ v[b] &+ y; v[d] = rotateRight(v[d] ^ v[a], by: 16); v[c] = v[c] &+ v[d]; v[b] = rotateRight(v[b] ^ v[c], by: 63)
    }

    private static func rotateRight(_ value: UInt64, by: Int) -> UInt64 { return (value >> by) | (value << (64 - by)) }
}
