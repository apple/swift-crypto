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

internal enum Argon2NativeImplementation {
    enum Variant: Int { case d = 0, i = 1, id = 2 }

    struct Block {
        var v: [UInt64]
        init() { self.v = [UInt64](repeating: 0, count: 128) }
        mutating func xor(with other: Block) { for i in 0..<128 { v[i] ^= other.v[i] } }
    }

    /// Pure Swift implementation of Argon2id as defined in RFC 9106.
    /// See: https://www.rfc-editor.org/rfc/rfc9106.html
    static func hash<P: DataProtocol, S: DataProtocol>(
        password: P, salt: S, iterations: Int, memoryBytes: Int, parallelism: Int, outputLength: Int,
        variant: Variant, secret: Data? = nil, associatedData: Data? = nil
    ) throws -> Data {
        let m = memoryBytes / 1024
        let p = parallelism; let t = iterations
        let m_prime = 4 * p * (m / (4 * p)); let q = m_prime / p
        
        var h0Input = Data()
        h0Input.append(contentsOf: withUnsafeBytes(of: UInt32(p).littleEndian) { Data($0) })
        h0Input.append(contentsOf: withUnsafeBytes(of: UInt32(outputLength).littleEndian) { Data($0) })
        h0Input.append(contentsOf: withUnsafeBytes(of: UInt32(m).littleEndian) { Data($0) })
        h0Input.append(contentsOf: withUnsafeBytes(of: UInt32(t).littleEndian) { Data($0) })
        h0Input.append(contentsOf: withUnsafeBytes(of: UInt32(0x13).littleEndian) { Data($0) })
        h0Input.append(contentsOf: withUnsafeBytes(of: UInt32(variant.rawValue).littleEndian) { Data($0) })
        
        func appendData<D: DataProtocol>(_ d: D) {
            h0Input.append(contentsOf: withUnsafeBytes(of: UInt32(d.count).littleEndian) { Data($0) })
            h0Input.append(contentsOf: d)
        }
        
        appendData(password); appendData(salt)
        appendData(secret ?? Data()); appendData(associatedData ?? Data())

        let h0 = Blake2b.hash(data: h0Input, outLength: 64)
        var blocks = [Block](repeating: Block(), count: p * q)

        for lane in 0..<p {
            for j in 0..<2 {
                var input = Data(h0)
                input.append(contentsOf: withUnsafeBytes(of: UInt32(j).littleEndian) { Data($0) })
                input.append(contentsOf: withUnsafeBytes(of: UInt32(lane).littleEndian) { Data($0) })
                blocks[lane * q + j] = dataToBlock(hPrime(data: input, length: 1024))
            }
        }

        for pass in 0..<t {
            for slice in 0..<4 {
                let sliceLen = q / 4
                var generators: [IndexGenerator?] = (0..<p).map { lane in
                    if variant == .i || (variant == .id && pass == 0 && slice < 2) {
                        return IndexGenerator(pass: pass, lane: lane, slice: slice, m_prime: m_prime, iterations: t, variant: variant)
                    }
                    return nil
                }
                for col in 0..<sliceLen {
                    let j = slice * sliceLen + col
                    if pass == 0 && j < 2 { continue }
                    for lane in 0..<p {
                        let (l, z) = computeIndices(pass: pass, lane: lane, slice: slice, col: col, sliceLen: sliceLen, p: p, q: q, variant: variant, blocks: blocks, generator: &generators[lane])
                        let prevCol = (j == 0 ? q - 1 : j - 1)
                        let nextBlock = g(x: blocks[lane * q + prevCol], y: blocks[l * q + z])
                        if pass == 0 { blocks[lane * q + j] = nextBlock }
                        else { blocks[lane * q + j].xor(with: nextBlock) }
                    }
                }
            }
        }

        var finalBlock = blocks[0 * q + (q - 1)]
        for i in 1..<p { finalBlock.xor(with: blocks[i * q + (q - 1)]) }
        return hPrime(data: blockToData(finalBlock), length: outputLength)
    }

    private static func g(x: Block, y: Block) -> Block {
        var r = Block()
        for i in 0..<128 { r.v[i] = x.v[i] ^ y.v[i] }
        let originalR = r
        
        for i in 0..<8 {
            applyPRound(&r.v, (0..<8).map { 8 * i + $0 })
        }
        for i in 0..<8 {
            applyPRound(&r.v, (0..<8).map { i + 8 * $0 })
        }
        
        for i in 0..<128 { r.v[i] ^= originalR.v[i] }
        return r
    }

    private static func applyPRound(_ v: inout [UInt64], _ indices: [Int]) {
        var s = [UInt64](repeating: 0, count: 16)
        for i in 0..<8 { s[2*i] = v[2*indices[i]]; s[2*i+1] = v[2*indices[i]+1] }
        
        func callGB(_ i0: Int, _ i1: Int, _ i2: Int, _ i3: Int) {
            var a = s[i0], b = s[i1], c = s[i2], d = s[i3]
            gb(&a, &b, &c, &d)
            s[i0] = a; s[i1] = b; s[i2] = c; s[i3] = d
        }
        
        callGB(0, 4, 8, 12)
        callGB(1, 5, 9, 13)
        callGB(2, 6, 10, 14)
        callGB(3, 7, 11, 15)
        
        callGB(0, 5, 10, 15)
        callGB(1, 6, 11, 12)
        callGB(2, 7, 8, 13)
        callGB(3, 4, 9, 14)
        
        for i in 0..<8 { v[2*indices[i]] = s[2*i]; v[2*indices[i]+1] = s[2*i+1] }
    }

    private static func gb(_ a: inout UInt64, _ b: inout UInt64, _ c: inout UInt64, _ d: inout UInt64) {
        func f(_ x: UInt64, _ y: UInt64) -> UInt64 {
            let x32 = x & 0xFFFFFFFF; let y32 = y & 0xFFFFFFFF
            return x &+ y &+ (2 &* x32 &* y32)
        }
        a = f(a, b); d = rotateRight(d ^ a, by: 32)
        c = f(c, d); b = rotateRight(b ^ c, by: 24)
        a = f(a, b); d = rotateRight(d ^ a, by: 16)
        c = f(c, d); b = rotateRight(b ^ c, by: 63)
    }

    private static func rotateRight(_ value: UInt64, by: Int) -> UInt64 { return (value >> by) | (value << (64 - by)) }

    private static func hPrime(data: Data, length: Int) -> Data {
        if length <= 64 {
            return Blake2b.hash(data: withUnsafeBytes(of: UInt32(length).littleEndian) { Data($0) } + data, outLength: length)
        }
        let r = (length + 31) / 32 - 2
        var result = Data()
        var v = Blake2b.hash(data: withUnsafeBytes(of: UInt32(length).littleEndian) { Data($0) } + data, outLength: 64)
        result.append(v.prefix(32))
        for _ in 0..<r-1 { v = Blake2b.hash(data: v, outLength: 64); result.append(v.prefix(32)) }
        v = Blake2b.hash(data: v, outLength: length - 32 * r); result.append(v)
        return result
    }

    private static func computeIndices(pass: Int, lane: Int, slice: Int, col: Int, sliceLen: Int, p: Int, q: Int, variant: Variant, blocks: [Block], generator: inout IndexGenerator?) -> (Int, Int) {
        var j1: UInt32 = 0; var j2: UInt32 = 0
        if generator != nil { (j1, j2) = generator!.nextPair() }
        else {
            let j = slice * sliceLen + col; let prevCol = (j - 1 + q) % q
            let v0 = blocks[lane * q + prevCol].v[0]
            j1 = UInt32(v0 & 0xFFFFFFFF); j2 = UInt32(v0 >> 32)
        }
        let l = (pass == 0 && slice == 0) ? lane : Int(j2 % UInt32(p))
        var refSize: Int
        if pass == 0 { refSize = (l == lane) ? (slice * sliceLen + col - 1) : (slice * sliceLen - (col == 0 ? 1 : 0)) }
        else { refSize = (l == lane) ? (q - sliceLen + col - 1) : (q - sliceLen - (col == 0 ? 1 : 0)) }
        if refSize < 1 { refSize = 1 }
        let z = (UInt64(refSize) * ((UInt64(j1) * UInt64(j1)) >> 32)) >> 32
        let relPos = refSize - 1 - Int(z)
        let absZ = (pass == 0) ? relPos : ((slice + 1) * sliceLen + relPos) % q
        return (l, absZ)
    }

    private struct IndexGenerator {
        var blocks: [UInt64]; var index: Int
        init(pass: Int, lane: Int, slice: Int, m_prime: Int, iterations: Int, variant: Variant) {
            var input = Block()
            input.v[0] = UInt64(pass); input.v[1] = UInt64(lane); input.v[2] = UInt64(slice)
            input.v[3] = UInt64(m_prime); input.v[4] = UInt64(iterations); input.v[5] = UInt64(variant.rawValue)
            self.blocks = []; self.index = 0; let zero = Block()
            for i in 1...100 { input.v[6] = UInt64(i); self.blocks.append(contentsOf: g(x: zero, y: g(x: zero, y: input)).v) }
        }
        mutating func nextPair() -> (UInt32, UInt32) {
            let j1 = UInt32(blocks[index] & 0xFFFFFFFF); let j2 = UInt32(blocks[index] >> 32)
            index += 1; return (j1, j2)
        }
    }

    private static func dataToBlock(_ data: Data) -> Block {
        var block = Block(); let bytes = [UInt8](data)
        for i in 0..<128 {
            let offset = i * 8; var val: UInt64 = 0
            for k in 0..<8 { val |= UInt64(bytes[offset + k]) << (k * 8) }
            block.v[i] = val
        }
        return block
    }

    private static func blockToData(_ block: Block) -> Data {
        var data = Data()
        for i in 0..<128 { withUnsafeBytes(of: block.v[i].littleEndian) { data.append(contentsOf: $0) } }
        return data
    }
}
