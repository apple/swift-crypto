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

// TODO: Provide an implementation using Security.framework.
fileprivate typealias BackingPublicKey = BoringSSLRSAPublicKey
fileprivate typealias BackingPrivateKey = BoringSSLRSAPrivateKey

extension _RSA {
    public enum BlindSigning {}
}

extension _RSA.BlindSigning {
    public struct PublicKey: Sendable {
        private var backing: BackingPublicKey

        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init(pemRepresentation: String) throws {
            self.backing = try BackingPublicKey(pemRepresentation: pemRepresentation)

            guard self.keySizeInBits >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init(unsafePEMRepresentation pemRepresentation: String) throws {
            self.backing = try BackingPublicKey(pemRepresentation: pemRepresentation)

            guard self.keySizeInBits >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }

        }

        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            self.backing = try BackingPublicKey(derRepresentation: derRepresentation)

            guard self.keySizeInBits >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init<Bytes: DataProtocol>(unsafeDERRepresentation derRepresentation: Bytes) throws {
            self.backing = try BackingPublicKey(derRepresentation: derRepresentation)

            guard self.keySizeInBits >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Construct an RSA public key with the specified parameters.
        ///
        /// This constructor is used in tests in cases where test vectors provide the key information this way.
        ///
        /// - TODO: Accept `ArbitraryPrecisionInteger` params once SPI is available to `_CryptoExtras`.
        internal init(nHexString: String, eHexString: String) throws {
            self.backing = try BackingPublicKey(nHexString: nHexString, eHexString: eHexString)
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

        fileprivate init(_ backing: BackingPublicKey) {
            self.backing = backing
        }
    }
}

extension _RSA.BlindSigning {
    public struct PrivateKey: Sendable {
        private var backing: BackingPrivateKey

        /// Construct an RSA private key from a PEM representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init(pemRepresentation: String) throws {
            self.backing = try BackingPrivateKey(pemRepresentation: pemRepresentation)

            guard self.keySizeInBits >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init(unsafePEMRepresentation pemRepresentation: String) throws {
            self.backing = try BackingPrivateKey(pemRepresentation: pemRepresentation)

            guard self.keySizeInBits >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Construct an RSA private key from a DER representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            self.backing = try BackingPrivateKey(derRepresentation: derRepresentation)

            guard self.keySizeInBits >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init<Bytes: DataProtocol>(unsafeDERRepresentation derRepresentation: Bytes) throws {
            self.backing = try BackingPrivateKey(derRepresentation: derRepresentation)

            guard self.keySizeInBits >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Randomly generate a new RSA private key of a given size.
        ///
        /// This constructor will refuse to generate keys smaller than 2048 bits. Callers that want to enforce minimum
        /// key size requirements should validate `keySize` before use.
        public init(keySize: _RSA.Signing.KeySize) throws {
            guard keySize.bitCount >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
            self.backing = try BackingPrivateKey(keySize: keySize)
        }

        /// Randomly generate a new RSA private key of a given size.
        ///
        /// This constructor will refuse to generate keys smaller than 1024 bits. Callers that want to enforce minimum
        /// key size requirements should validate `unsafekeySize` before use.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init(unsafeKeySize keySize: _RSA.Signing.KeySize) throws {
            guard keySize.bitCount >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }
            self.backing = try BackingPrivateKey(keySize: keySize)
        }

        /// Construct an RSA private key with the specified parameters.
        ///
        /// This constructor is used in tests in cases where test vectors provide the key information this way.
        ///
        /// - TODO: Accept `ArbitraryPrecisionInteger` params once SPI is available to `_CryptoExtras`.
        internal init(nHexString: String, eHexString: String, dHexString: String) throws {
            self.backing = try BackingPrivateKey(nHexString: nHexString, eHexString: eHexString, dHexString: dHexString)
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

        public var publicKey: _RSA.BlindSigning.PublicKey {
            _RSA.BlindSigning.PublicKey(self.backing.publicKey)
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
    /// Users should not attempt to create parameters manaully and should use one of the static properties for
    /// a standard RSABSSA variant.
    ///
    /// The RECOMMENDED variants are RSABSSA-SHA384-PSS-Randomized or RSABSSA-SHA384-PSSZERO-Randomized.
    ///
    /// - Seealso: [RFC 9474: RSABSSA Variants](https://www.rfc-editor.org/rfc/rfc9474.html#name-rsabssa-variants).
    public struct Parameters<H: HashFunction> {
        enum Preparation { case identity, randomized }
        var padding: _RSA.Signing.Padding
        var preparation: Preparation
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

extension _RSA.BlindSigning.PrivateKey {
    /// Generate a blind signature with the given key for a blinded message.
    ///
    /// - Parameter blindedMessage: The blinded message to sign.
    /// - Returns: A blind signature.
    /// - Throws: If there is a failure producing the signature.
    ///
    /// - Seealso: [RFC 9474: BlindSign](https://www.rfc-editor.org/rfc/rfc9474.html#name-blindsign).
    /// - TODO: Should this accept a new `BlindedMesage` type to help guide protocol usage?
    public func blindSignature<D: DataProtocol>(for blindedMessage: D) throws -> _RSA.BlindSigning.BlindSignature {
        try self.backing.blindSignature(blindedMessage)
    }
}


extension _RSA.BlindSigning {
    /// Prepare a message to be signed using the blind signing protocol.
    ///
    /// - Parameter message: The message to be signed.
    /// - Parameter pararmeters: The parameters for the blind signing protocol.
    /// - Returns: A preprared mesage, modified according to the parameters provided.
    ///
    /// - Seealso: [RFC 9474: Prepare](https://www.rfc-editor.org/rfc/rfc9474.html#name-prepare).
    ///
    /// - TODO: Needs `SecureBytes` SPI from `Crypto`.
    /// - TODO: Should this return a new `PreparedMessage` type to help guide protocol usage?
    /* public when ready */ static func prepare<D: DataProtocol, H: HashFunction>(
        _ message: D,
        parameters: _RSA.BlindSigning.Parameters<H> = .RSABSSA_SHA384_PSS_Randomized
    ) -> some DataProtocol {
        switch parameters.preparation {
        case .identity: return Data(message)
        case .randomized: // return Data(SecureBytes(count: 32) + message)
            fatalError("not yet implemented")
        }
    }
}

extension _RSA.BlindSigning.PublicKey {
    /// Blind a message to be signed by the server using the blind signing protocol.
    ///
    /// - Parameter message: The message to be signed.
    /// - Parameter pararmeters: The parameters for the blind signing protocol.
    /// - Returns: The blinded message, and its inverse for unblinding its blind signature.
    ///
    /// - Seealso: [RFC 9474: Blind](https://www.rfc-editor.org/rfc/rfc9474.html#name-blind).
    ///
    /// - TODO: Needs `ArbitraryPrecisionInteger` SPI from `Crypto`.
    /// - TODO: Should this accept a new `PreparedMessage` type to help guide protocol usage?
    /// - TODO: Should this return a new `BlindedMessage` type to help guide protocol usage?
    /* public when ready */ func blind<D: DataProtocol, H: HashFunction>(
        _ message: D,
        parameters: _RSA.BlindSigning.Parameters<H> = .RSABSSA_SHA384_PSS_Randomized
    ) throws -> (blindedMessage: /* some DataProtocol */ Any, blindInverse: /* ArbitraryPrecisionInteger when available */ Any) {
        fatalError("not yet implemented")
    }

    /// Unblinds the message and produce a signature for the message.
    ///
    /// - Parameter blindSignature: The signature of the blinded message.
    /// - Parameter message: The message to be signed.
    /// - Parameter blindInverse: The inverse from the message blinding.
    /// - Parameter pararmeters: The parameters for the blind signing protocol.
    /// - Returns: The signature of the message.
    ///
    /// - Seealso: [RFC 9474: Finalize](https://www.rfc-editor.org/rfc/rfc9474.html#name-finalize).
    ///
    /// - TODO: Needs `ArbitraryPrecisionInteger` SPI from `Crypto`.
    /// - TODO: Should this accept a new `PreparedMessage` type to help guide protocol usage?
    /* public when ready */ func finalize<D: DataProtocol, H: HashFunction>(
        _ blindSignature: _RSA.BlindSigning.BlindSignature,
        for message: D,
        blindInverse: /* ArbitraryPrecisionInteger when available */ Any,
        parameters: _RSA.BlindSigning.Parameters<H> = .RSABSSA_SHA384_PSS_Randomized
    ) throws -> _RSA.Signing.RSASignature {
        fatalError("not yet implemented")
    }

    /// Validate a signature for a prepared message.
    ///
    /// - Parameter signature: The signature to verify.
    /// - Parameter message: The message the signature is for.
    /// - Parameter pararmeters: The parameters for the blind signing protocol.
    /// - Returns: True if the signature is valid; false otherwise.
    ///
    /// - Seealso: [RFC 9474: Verification](https://www.rfc-editor.org/rfc/rfc9474.html#name-verification).
    ///
    /// - TODO: Needs `ArbitraryPrecisionInteger` SPI from `Crypto`.
    /// - TODO: Should this accept a new `PreparedMessage` type to help guide protocol usage?
    public func isValidSignature<D: DataProtocol, H: HashFunction>(
        _ signature: _RSA.Signing.RSASignature,
        for message: D,
        parameters: _RSA.BlindSigning.Parameters<H> = .RSABSSA_SHA384_PSS_Randomized
    ) -> Bool {
        let digest = H.hash(data: message)
        return self.backing.isValidSignature(signature, for: digest, padding: parameters.padding)
    }
}
