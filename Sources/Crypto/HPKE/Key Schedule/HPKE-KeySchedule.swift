//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
import SwiftSystem
#else
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension HPKE {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    internal struct KeySchedule: Sendable {
        fileprivate static let pksIDHashLabel = Data("psk_id_hash".utf8)
        fileprivate static let infoHashLabel = Data("info_hash".utf8)
        fileprivate static let secretLabel = Data("secret".utf8)
        fileprivate static let keyLabel = Data("key".utf8)
        fileprivate static let baseLabel = Data("base_nonce".utf8)
        fileprivate static let exporterLabel = Data("exp".utf8)
        
        var sequenceNumber: UInt64 = 0
        var key: SymmetricKey?
        var nonce: Data?
        var exporterSecret: SymmetricKey
        var ciphersuite: HPKE.Ciphersuite
        
        static func verifyPSKInputs(mode: HPKE.Mode, psk: SymmetricKey?, pskID: Data?) throws {
            let gotPSK = (psk != nil)
            let gotPSKID = (pskID != nil)
            
            if gotPSK != gotPSKID {
                throw HPKE.Errors.inconsistentPSKInputs
            }
            
            if gotPSK && !HPKE.Mode.pskModes.contains(mode) {
                throw HPKE.Errors.unexpectedPSK
            }
            
            if !gotPSK && HPKE.Mode.pskModes.contains(mode) {
                throw HPKE.Errors.expectedPSK
            }
        }
        
        init(mode: HPKE.Mode, sharedSecret: ContiguousBytes, info: Data, psk: SymmetricKey?, pskID: Data?, ciphersuite: Ciphersuite) throws {
            try HPKE.KeySchedule.verifyPSKInputs(mode: mode, psk: psk, pskID: pskID)
            
            let pskIDHash = NonSecretOutputLabeledExtract(salt: nil,
                                                          label: HPKE.KeySchedule.pksIDHashLabel,
                                                          ikm: pskID.map { SymmetricKey(data: $0) },
                                                          suiteID: ciphersuite.identifier,
                                                          kdf: ciphersuite.kdf)
            
            let infoHash = NonSecretOutputLabeledExtract(salt: nil,
                                                         label: HPKE.KeySchedule.infoHashLabel,
                                                         ikm: SymmetricKey(data: info),
                                                         suiteID: ciphersuite.identifier,
                                                         kdf: ciphersuite.kdf)
            
            var keyScheduleContext = Data()
            keyScheduleContext.append(mode.value)
            keyScheduleContext.append(pskIDHash)
            keyScheduleContext.append(infoHash)
            
            let secret = LabeledExtract(salt: Data(unsafeFromContiguousBytes: sharedSecret),
                                        label: HPKE.KeySchedule.secretLabel,
                                        ikm: psk.map { SymmetricKey(data: $0) },
                                        suiteID: ciphersuite.identifier,
                                        kdf: ciphersuite.kdf)
            
            if !ciphersuite.aead.isExportOnly {
                self.key = LabeledExpand(prk: secret,
                                         label: HPKE.KeySchedule.keyLabel,
                                         info: keyScheduleContext,
                                         outputByteCount: UInt16(ciphersuite.aead.keyByteCount),
                                         suiteID: ciphersuite.identifier,
                                         kdf: ciphersuite.kdf)
                
                self.nonce = NonSecretOutputLabeledExpand(prk: secret,
                                                          label: HPKE.KeySchedule.baseLabel,
                                                          info: keyScheduleContext,
                                                          outputByteCount: UInt16(ciphersuite.aead.nonceByteCount),
                                                          suiteID: ciphersuite.identifier,
                                                          kdf: ciphersuite.kdf)
            }
            
            self.exporterSecret = LabeledExpand(prk: secret,
                                                label: HPKE.KeySchedule.exporterLabel,
                                                info: keyScheduleContext,
                                                outputByteCount: UInt16(ciphersuite.kdf.Nh),
                                                suiteID: ciphersuite.identifier,
                                                kdf: ciphersuite.kdf)
            
            
            self.ciphersuite = ciphersuite
        }
        
        var maxSequenceNumber: UInt64 {
            get {
                let nonceBitCount = UInt64(self.ciphersuite.aead.nonceByteCount * 8)
                if (nonceBitCount >= 64) {
                    return UInt64.max
                }
                
                return ((UInt64(1) << nonceBitCount) - 1)
            }
        }
        
        mutating func incrementSequenceNumber() throws {
            if self.sequenceNumber >= maxSequenceNumber {
                throw HPKE.Errors.outOfRangeSequenceNumber
            }
            sequenceNumber += 1
        }
        
        mutating func seal<M: DataProtocol, AD: DataProtocol>(_ msg: M, authenticating aad: AD) throws -> Data {
            guard !self.ciphersuite.aead.isExportOnly else {
                throw HPKE.Errors.exportOnlyMode
            }
            
            let ct = try ciphersuite.aead.seal(msg, authenticating: aad, nonce: currentNonce, using: self.key!)
            try incrementSequenceNumber()
            return ct
        }
        
        mutating func open<C: DataProtocol, AD: DataProtocol>(_ ciphertext: C, authenticating aad: AD) throws -> Data {
            guard !self.ciphersuite.aead.isExportOnly else {
                throw HPKE.Errors.exportOnlyMode
            }
            
            let pt = try ciphersuite.aead.open(ciphertext, nonce: currentNonce, authenticating: aad, using: self.key!)
            try incrementSequenceNumber()
            return pt
        }
        
        var currentNonce: Data {
            var nonceData = [UInt8](repeating: 0, count: ciphersuite.aead.nonceByteCount - MemoryLayout.size(ofValue: sequenceNumber))
            var bigEndian = sequenceNumber.bigEndian
            withUnsafeBytes(of: &(bigEndian)) { (bufferPointer) in
                nonceData.append(contentsOf: bufferPointer)
            }
            let nonce = self.nonce!
            precondition(nonce.count == nonceData.count)
            return Data(zip(nonceData, nonce).lazy.map { $0.0 ^ $0.1 })
        }
    }
}

#endif // Linux or !SwiftPM
