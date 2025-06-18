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
#if canImport(FoundationEssentials)
#if os(Windows)
import ucrt
#elseif canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#elseif canImport(WASILibc)
import WASILibc
#endif
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Data {
    static func ^ (left: Data, right: Data) -> Data {
        precondition(left.count == right.count)
        var result = Data()
        result.reserveCapacity(left.count)
        for value in zip(left, right) {
            result.append(value.0 ^ value.1)
        }
        return result
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum Hash2FieldErrors: Error {
    case outputSizeIsTooLarge
}

/// HashToField hashes a byte string msg of arbitrary length into one or more elements of a finite field
@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
struct HashToField<C: SupportedCurveDetailsImpl> {
    static func expandMessageXMD(_ msg: Data, DST: Data, outputByteCount L: Int) throws -> Data {
        typealias H = C.H
        let digestByteCount = H.Digest.byteCount
        
        let ell = Int(ceil(Double(L) / Double(digestByteCount)))
        
        if ell > 255 {
            throw Hash2FieldErrors.outputSizeIsTooLarge
        }
        
        let DST_prime = DST + I2OSP(value: DST.count, outputByteCount: 1)
        let z_pad = Data(repeating: 0, count: H.blockByteCount)
        let l_i_b_str = I2OSP(value: L, outputByteCount: 2)
        let msg_prime = z_pad + msg + l_i_b_str + I2OSP(value: 0, outputByteCount: 1) + DST_prime
        
        let b0 = Data(H.hash(data: msg_prime))
        var bis = Data()
        
        for i in 1...ell {
            let chaining = ((i == 1) ? b0 : (b0 ^ bis.suffix(digestByteCount)))
            bis.append(Data(H.hash(data: (chaining + I2OSP(value: i, outputByteCount: 1) + DST_prime))))
        }
        
        return Data(bis.prefix(L))
    }
    
    static func hashToField(_ data: Data, outputElementCount: Int, dst: Data, outputSize L: Int, reductionIsModOrder: Bool) throws -> [GroupImpl<C>.Scalar] {
        precondition(outputElementCount > 0)
        let byteCount = outputElementCount * L
        let uniformBytes = try expandMessageXMD(data,
                                                DST: dst,
                                                outputByteCount: byteCount)
        
        var u_i = [GroupImpl<C>.Scalar]()
        u_i.reserveCapacity(outputElementCount)
        
        for i in 0..<outputElementCount {
            let offset = i * L
            let tv = uniformBytes.subdata(in: offset..<(offset + L))
            u_i.append(try GroupImpl<C>.Scalar(bytes: tv, reductionIsModOrder: reductionIsModOrder))
        }
        
        precondition(u_i.count == outputElementCount)
        return u_i
    }
}
