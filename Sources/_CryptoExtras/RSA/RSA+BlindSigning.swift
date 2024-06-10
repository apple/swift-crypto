//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
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

// NOTE: RSABSSA API is implemented using BoringSSL on all platforms.
fileprivate typealias BackingPublicKey = BoringSSLRSAPublicKey
fileprivate typealias BackingPrivateKey = BoringSSLRSAPrivateKey

extension _RSA {
    public enum BlindSigning {}
}

extension _RSA.BlindSigning {
    public struct PublicKey<H: HashFunction>: Sendable {
        public typealias Parameters = _RSA.BlindSigning.Parameters<H>

        private var backing: BackingPublicKey
        private let parameters: Parameters

        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init(pemRepresentation: String, parameters: Parameters = .RSABSSA_SHA384_PSS_Randomized) throws {
            self.backing = try BackingPublicKey(pemRepresentation: pemRepresentation)
            self.parameters = parameters

            guard self.keySizeInBits >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init(unsafePEMRepresentation pemRepresentation: String, parameters: Parameters = .RSABSSA_SHA384_PSS_Randomized) throws {
            self.backing = try BackingPublicKey(pemRepresentation: pemRepresentation)
            self.parameters = parameters

            guard self.keySizeInBits >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes, parameters: Parameters = .RSABSSA_SHA384_PSS_Randomized) throws {
            self.backing = try BackingPublicKey(derRepresentation: derRepresentation)
            self.parameters = parameters

            guard self.keySizeInBits >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init<Bytes: DataProtocol>(unsafeDERRepresentation derRepresentation: Bytes, parameters: Parameters = .RSABSSA_SHA384_PSS_Randomized) throws {
            self.backing = try BackingPublicKey(derRepresentation: derRepresentation)
            self.parameters = parameters

            guard self.keySizeInBits >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        public var pkcs1DERRepresentation: Data {
            self.backing.pkcs1DERRepresentation
        }

        public var pkcs1PEMRepresentation: String {
            self.backing.pkcs1PEMRepresentation
        }

        public var derRepresentation: Data {
            self.backing.derRepresentation
        }

        public var pemRepresentation: String {
            self.backing.pemRepresentation
        }

        public var keySizeInBits: Int {
            self.backing.keySizeInBits
        }

        fileprivate init(_ backing: BackingPublicKey, _ parameters: Parameters) {
            self.backing = backing
            self.parameters = parameters
        }
    }
}

extension _RSA.BlindSigning {
    public struct PrivateKey<H: HashFunction>: Sendable {
        public typealias Parameters = _RSA.BlindSigning.Parameters<H>

        private var backing: BackingPrivateKey
        private let parameters: Parameters

        /// Construct an RSA private key from a PEM representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init(pemRepresentation: String, parameters: Parameters = .RSABSSA_SHA384_PSS_Randomized) throws {
            self.backing = try BackingPrivateKey(pemRepresentation: pemRepresentation)
            self.parameters = parameters

            guard self.keySizeInBits >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Construct an RSA private key from a PEM representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init(unsafePEMRepresentation pemRepresentation: String, parameters: Parameters = .RSABSSA_SHA384_PSS_Randomized) throws {
            self.backing = try BackingPrivateKey(pemRepresentation: pemRepresentation)
            self.parameters = parameters

            guard self.keySizeInBits >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Construct an RSA private key from a DER representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes, parameters: Parameters = .RSABSSA_SHA384_PSS_Randomized) throws {
            self.backing = try BackingPrivateKey(derRepresentation: derRepresentation)
            self.parameters = parameters

            guard self.keySizeInBits >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Construct an RSA private key from a DER representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init<Bytes: DataProtocol>(unsafeDERRepresentation derRepresentation: Bytes, parameters: Parameters = .RSABSSA_SHA384_PSS_Randomized) throws {
            self.backing = try BackingPrivateKey(derRepresentation: derRepresentation)
            self.parameters = parameters

            guard self.keySizeInBits >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Randomly generate a new RSA private key of a given size.
        ///
        /// This constructor will refuse to generate keys smaller than 2048 bits. Callers that want to enforce minimum
        /// key size requirements should validate `keySize` before use.
        public init(keySize: _RSA.Signing.KeySize, parameters: Parameters = .RSABSSA_SHA384_PSS_Randomized) throws {
            guard keySize.bitCount >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
            self.backing = try BackingPrivateKey(keySize: keySize)
            self.parameters = parameters
        }

        /// Randomly generate a new RSA private key of a given size.
        ///
        /// This constructor will refuse to generate keys smaller than 1024 bits. Callers that want to enforce minimum
        /// key size requirements should validate `unsafekeySize` before use.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init(unsafeKeySize keySize: _RSA.Signing.KeySize, parameters: Parameters = .RSABSSA_SHA384_PSS_Randomized) throws {
            guard keySize.bitCount >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }
            self.backing = try BackingPrivateKey(keySize: keySize)
            self.parameters = parameters
        }

        public var derRepresentation: Data {
            self.backing.derRepresentation
        }

        public var pemRepresentation: String {
            self.backing.pemRepresentation
        }

        public var pkcs8PEMRepresentation: String {
            self.backing.pkcs8PEMRepresentation
        }

        public var keySizeInBits: Int {
            self.backing.keySizeInBits
        }

        public var publicKey: _RSA.BlindSigning.PublicKey<H> {
            _RSA.BlindSigning.PublicKey(self.backing.publicKey, self.parameters)
        }
    }
}

extension _RSA.BlindSigning {
    public struct BlindSignature: Sendable, ContiguousBytes {
        public var rawRepresentation: Data

        public init<D: DataProtocol>(rawRepresentation: D) {
            self.rawRepresentation = Data(rawRepresentation)
        }

        internal init(signatureBytes: [UInt8]) {
            self.rawRepresentation = Data(signatureBytes)
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }
    }
}

extension _RSA.BlindSigning {
    /// Parameters used in the blind signing protocol.
    ///
    /// Users cannot create parameters manually and should use one of the static properties for
    /// a standard RSABSSA variant.
    ///
    /// The RECOMMENDED variants are RSABSSA-SHA384-PSS-Randomized or RSABSSA-SHA384-PSSZERO-Randomized.
    ///
    /// - Seealso: [RFC 9474: RSABSSA Variants](https://www.rfc-editor.org/rfc/rfc9474.html#name-rsabssa-variants).
    public struct Parameters<H: HashFunction>: Sendable {
        enum Padding { case PSS, PSSZERO }
        var padding: Padding

        enum Preparation { case identity, randomized }
        var preparation: Preparation

        var saltLength: Int32 {
            switch self.padding {
            case .PSS: return Int32(H.Digest.byteCount)
            case .PSSZERO: return 0
            }
        }
    }
}

extension _RSA.BlindSigning.Parameters where H == SHA384 {
    /// RSABSSA-SHA384-PSS-Randomized
    ///
    /// This named variant uses SHA-384 as the EMSA-PSS Hash option, MGF1 with SHA-384 as the EMSA-PSS MGF option,
    /// and 48 as the EMSA-PSS sLen option (48-byte salt length); it also uses the randomized preparation function.
    ///
    /// - Seealso: [RFC 9474: RSABSSA Variants](https://www.rfc-editor.org/rfc/rfc9474.html#name-rsabssa-variants).
    public static let RSABSSA_SHA384_PSS_Randomized = Self<SHA384>(padding: .PSS, preparation: .randomized)

    /// RSABSSA-SHA384-PSSZERO-Randomized
    ///
    /// This named variant uses SHA-384 as the EMSA-PSS Hash option, MGF1 with SHA-384 as the EMSA-PSS MGF option,
    /// and 0 as the EMSA-PSS sLen option (0-byte salt length); it also uses the randomized preparation function.
    ///
    /// - Seealso: [RFC 9474: RSABSSA Variants](https://www.rfc-editor.org/rfc/rfc9474.html#name-rsabssa-variants).
    public static let RSABSSA_SHA384_PSSZERO_Randomized = Self<SHA384>(padding: .PSSZERO, preparation: .randomized)

    /// RSABSSA-SHA384-PSS-Deterministic
    ///
    /// This named variant uses SHA-384 as the EMSA-PSS Hash option, MGF1 with SHA-384 as the EMSA-PSS MGF option,
    /// and 48 as the EMSA-PSS sLen option (48-byte salt length); it also uses the identity preparation function.
    ///
    /// - WARNING: Not all named variants can be used interchangeably. In particular, applications that provide
    /// high-entropy input messages can safely use named variants without randomized message preparation, as the
    /// additional message randomization does not offer security advantages.
    /// For all other applications, the variants that use the randomized preparation function protect clients from
    /// malicious signers.
    ///
    /// - Seealso: [RFC 9474: RSABSSA Variants](https://www.rfc-editor.org/rfc/rfc9474.html#name-rsabssa-variants).
    public static let RSABSSA_SHA384_PSS_Deterministic = Self<SHA384>(padding: .PSS, preparation: .identity)

    /// RSABSSA-SHA384-PSSZERO-Deterministic
    ///
    /// This named variant uses SHA-384 as the EMSA-PSS Hash option, MGF1 with SHA-384 as the EMSA-PSS MGF option,
    /// and 0 as the EMSA-PSS sLen option (0-byte salt length); it also uses the identity preparation function
    ///
    /// - NOTE: This is the only variant that produces deterministic signatures over the client's input message.
    ///
    /// - WARNING: Applications that require deterministic signatures can use the RSABSSA-SHA384-PSSZERO-Deterministic
    /// variant, but only if their input messages have high entropy. Applications that use
    /// RSABSSA-SHA384-PSSZERO-Deterministic SHOULD carefully analyze the security implications, taking into account
    /// the possibility of adversarially generated signer keys as described in Section 7.3. When it is not clear whether
    /// an application requires deterministic or randomized signatures, applications SHOULD use one of the variants with
    /// randomized message preparation.
    ///
    /// - Seealso: [RFC 9474: RSABSSA Variants](https://www.rfc-editor.org/rfc/rfc9474.html#name-rsabssa-variants).
    public static let RSABSSA_SHA384_PSSZERO_Deterministic = Self<SHA384>(padding: .PSSZERO, preparation: .identity)
}

extension _RSA.BlindSigning {
    /// An input ready to be blinded, possibly prepended with random bytes.
    ///
    /// Users cannot create values of this type manually; it is created and returned by the prepare operation.
    public struct PreparedMessage {
        var rawRepresentation: Data
    }

    /// The blinding inverse for a blinded message, used to unblind a blind signature.
    ///
    /// Users cannot create values of this type manually; it is created and returned by the blind operation.
    public struct BlindingInverse {
        var rawRepresentation: Data
    }

    /// The blinded message and its blinding inverse for unblinding its blind signature.
    ///
    /// Users cannot create values of this type manually; it is created and returned by the blind operation.
    public struct BlindingResult {
        /// Blinded message to be sent to the issuer.
        public var blindedMessage: Data

        /// Blinding inverse for producing a signature for the prepared message from the blinded signature.
        public var inverse: BlindingInverse
    }
}

extension _RSA.BlindSigning.PrivateKey {
    /// Generate a blind signature with the given key for a blinded message.
    ///
    /// - Parameter message: The blinded message to sign.
    /// - Returns: A blind signature.
    /// - Throws: If there is a failure producing the signature.
    ///
    /// - Seealso: [RFC 9474: BlindSign](https://www.rfc-editor.org/rfc/rfc9474.html#name-blindsign).
    public func blindSignature<D: DataProtocol>(for message: D) throws -> _RSA.BlindSigning.BlindSignature {
        try self.backing.blindSignature(for: message)
    }
}

extension _RSA.BlindSigning.PublicKey {
    /// Prepare a message to be signed using the blind signing protocol.
    ///
    /// - Parameter message: The message to be signed.
    /// - Parameter parameters: Parameters used in the blind signing protocol.
    /// - Returns: A prepared message, modified according to the parameters provided.
    ///
    /// - Seealso: [RFC 9474: Prepare](https://www.rfc-editor.org/rfc/rfc9474.html#name-prepare).
    public func prepare<D: DataProtocol>(_ message: D) -> _RSA.BlindSigning.PreparedMessage {
        switch self.parameters.preparation {
        case .identity:
            return _RSA.BlindSigning.PreparedMessage(rawRepresentation: Data(message))
        case .randomized:
            var preparedMessageBytes = Data(capacity: 32 + message.count)
            preparedMessageBytes.append(contentsOf: SystemRandomNumberGenerator.randomBytes(count: 32))
            preparedMessageBytes.append(contentsOf: message)
            return _RSA.BlindSigning.PreparedMessage(rawRepresentation: preparedMessageBytes)
        }
    }

    /// Blind a message to be signed by the server using the blind signing protocol.
    ///
    /// - Parameter message: The message to be signed.
    /// - Returns: The blinded message, and its inverse for unblinding its blind signature.
    ///
    /// - Seealso: [RFC 9474: Blind](https://www.rfc-editor.org/rfc/rfc9474.html#name-blind).
    public func blind(_ message: _RSA.BlindSigning.PreparedMessage) throws -> _RSA.BlindSigning.BlindingResult {
        try self.backing.blind(message, parameters: self.parameters)
    }

    /// Unblinds the message and produce a signature for the message.
    ///
    /// - Parameter signature: The signature of the blinded message.
    /// - Parameter message: The message to be signed.
    /// - Parameter blindInverse: The inverse from the message blinding.
    /// - Returns: The signature of the message.
    ///
    /// - Seealso: [RFC 9474: Finalize](https://www.rfc-editor.org/rfc/rfc9474.html#name-finalize).
    public func finalize(
        _ signature: _RSA.BlindSigning.BlindSignature,
        for message: _RSA.BlindSigning.PreparedMessage,
        blindingInverse: _RSA.BlindSigning.BlindingInverse
    ) throws -> _RSA.Signing.RSASignature {
        try self.backing.finalize(signature, for: message, blindingInverse: blindingInverse, parameters: self.parameters)
    }

    /// Validate a signature for a prepared message.
    ///
    /// - Parameter signature: The signature to verify.
    /// - Parameter message: The prepared message used in the blind signature protocol.
    /// - Returns: True if the signature is valid; false otherwise.
    ///
    /// - Seealso: [RFC 9474: Verification](https://www.rfc-editor.org/rfc/rfc9474.html#name-verification).
    public func isValidSignature(
        _ signature: _RSA.Signing.RSASignature,
        for message: _RSA.BlindSigning.PreparedMessage
    ) -> Bool {
        switch parameters.padding {
        case .PSS:
            return self.backing.isValidSignature(signature, for: H.hash(data: message.rawRepresentation), padding: .PSS)
        case .PSSZERO:
            return self.backing.isValidSignature(signature, for: H.hash(data: message.rawRepresentation), padding: .PSSZERO)
        }
    }
}

extension _RSA.BlindSigning {
    /// Errors defined in the RSA Blind Signatures protocol.
    ///
    /// - NOTE: This type does not conform to `Swift.Error`, it is used to construct a `CryptoKitError`.
    ///
    /// - Seealso: [RFC 9474: Errors](https://www.rfc-editor.org/rfc/rfc9474.html#name-errors).
    enum ProtocolError {
        case messageTooLong
        case encodingError
        case invalidInput
        case signingFailure
        case messageRepresentativeOutOfRange
        case invalidSignature
        case unexpectedInputSize
    }
}

extension CryptoKitError {
    /// Map an error from the RSA Blind Signatures protocol to a CryptoKitError.
    init(_ error: _RSA.BlindSigning.ProtocolError) {
        switch error {
        case .messageTooLong:
            self = .incorrectParameterSize
        case .encodingError:
            self = .incorrectParameterSize
        case .invalidInput:
            self = .incorrectParameterSize
        case .signingFailure:
            self = .authenticationFailure
        case .messageRepresentativeOutOfRange:
            self = .incorrectParameterSize
        case .invalidSignature:
            self = .authenticationFailure
        case .unexpectedInputSize:
            self = .incorrectParameterSize
        }
    }
}
