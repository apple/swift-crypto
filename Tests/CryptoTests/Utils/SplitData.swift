//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Foundation
import Dispatch

// A testing utility that creates one contiguous and one discontiguous representation of the given Data.
extension Array where Element == UInt8 {
    func asDataProtocols() -> (contiguous: Data, discontiguous: DispatchData) {
        guard self.count > 0 else {
            // We can't really have discontiguous options here, so we just return empty versions
            // of both.
            return (Data(), DispatchData.empty)
        }

        let contiguous = Data(self)
        let discontiguous: DispatchData = self.withUnsafeBytes { bytesPointer in
            let pivot = bytesPointer.count / 2
            var data = DispatchData.empty
            data.append(DispatchData(bytes: UnsafeRawBufferPointer(rebasing: bytesPointer[..<pivot])))
            data.append(DispatchData(bytes: UnsafeRawBufferPointer(rebasing: bytesPointer[pivot...])))
            return data
        }

        return (contiguous: contiguous, discontiguous: discontiguous)
    }
}
