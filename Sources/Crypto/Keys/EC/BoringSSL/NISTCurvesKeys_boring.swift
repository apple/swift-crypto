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
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
import Foundation

@usableFromInline
protocol OpenSSLSupportedNISTCurve {
    @inlinable
    static var group: BoringSSLEllipticCurveGroup { get }
}

extension OpenSSLSupportedNISTCurve {
    @inlinable
    static var coordinateByteCount: Int {
        return self.group.coordinateByteCount
    }
}

extension P256 {
    @usableFromInline
    struct CurveDetails: OpenSSLSupportedNISTCurve {
        @inlinable
        static var group: BoringSSLEllipticCurveGroup {
            return try! BoringSSLEllipticCurveGroup(.p256)
        }
    }
}

extension P384 {
    @usableFromInline
    struct CurveDetails: OpenSSLSupportedNISTCurve {
        @inlinable
        static var group: BoringSSLEllipticCurveGroup {
            return try! BoringSSLEllipticCurveGroup(.p384)
        }
    }
}

extension P521 {
    @usableFromInline
    struct CurveDetails: OpenSSLSupportedNISTCurve {
        @inlinable
        static var group: BoringSSLEllipticCurveGroup {
            return try! BoringSSLEllipticCurveGroup(.p521)
        }
    }
}

@usableFromInline
struct OpenSSLNISTCurvePrivateKeyImpl<Curve: OpenSSLSupportedNISTCurve> {
    @usableFromInline
    var key: BoringSSLECPrivateKeyWrapper<Curve>

    init(compactRepresentable: Bool = true) {
        self.key = try! BoringSSLECPrivateKeyWrapper(compactRepresentable: compactRepresentable)
    }

    init<Bytes: ContiguousBytes>(x963: Bytes) throws {
        self.key = try BoringSSLECPrivateKeyWrapper(x963Representation: x963)
    }

    init<Bytes: ContiguousBytes>(data: Bytes) throws {
        self.key = try BoringSSLECPrivateKeyWrapper(rawRepresentation: data)
    }

    func publicKey() -> OpenSSLNISTCurvePublicKeyImpl<Curve> {
        return OpenSSLNISTCurvePublicKeyImpl(wrapping: self.key.publicKey)
    }

    var rawRepresentation: Data {
        return self.key.rawRepresentation
    }

    var x963Representation: Data {
        return self.key.x963Representation
    }
}

@usableFromInline
struct OpenSSLNISTCurvePublicKeyImpl<Curve: OpenSSLSupportedNISTCurve> {
    @usableFromInline
    var key: BoringSSLECPublicKeyWrapper<Curve>

    init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
        self.key = try BoringSSLECPublicKeyWrapper(compactRepresentation: compactRepresentation)
    }

    init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
        self.key = try BoringSSLECPublicKeyWrapper(x963Representation: x963Representation)
    }

    init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
        self.key = try BoringSSLECPublicKeyWrapper(rawRepresentation: rawRepresentation)
    }

    @inlinable
    init(wrapping key: BoringSSLECPublicKeyWrapper<Curve>) {
        self.key = key
    }

    @inlinable
    var compactRepresentation: Data? {
        return self.key.compactRepresentation
    }

    @inlinable
    var rawRepresentation: Data {
        return self.key.rawRepresentation
    }

    @inlinable
    var x963Representation: Data {
        return self.key.x963Representation
    }
}

/// A simple wrapper for an EC_KEY pointer for a private key. This manages the lifetime of that pointer and
/// allows some helper operations.
@usableFromInline
class BoringSSLECPrivateKeyWrapper<Curve: OpenSSLSupportedNISTCurve> {
    @usableFromInline
    var key: OpaquePointer

    init(compactRepresentable: Bool) throws {
        // We cannot handle allocation failure.
        let group = Curve.group
        self.key = try! group.makeUnsafeOwnedECKey()

        // If we've been asked to generate a compact representable key, we need to try a few times. This loop shouldn't
        // execute more than 100 times: if it does, we'll crash because something bad is happening.
        for _ in 0 ..< 100 {
            // We generate FIPS compliant keys to match the behaviour of CryptoKit on Apple platforms.
            guard CCryptoBoringSSL_EC_KEY_generate_key(self.key) != 0 else {
                throw CryptoKitError.internalBoringSSLError()
            }

            // We want to generate FIPS compliant keys. If this isn't, loop around again.
            if CCryptoBoringSSL_EC_KEY_check_fips(self.key) == 0 {
                continue
            }

            if !compactRepresentable || _isCompactRepresentable(group: group, publicKeyPoint: self.publicKeyPoint) {
                return
            }
        }

        fatalError("Looped more than 100 times trying to generate a key")
    }

    init<Bytes: ContiguousBytes>(x963Representation bytes: Bytes) throws {
        // Before we do anything, we validate that the x963 representation has the right number of bytes.
        // This is because BoringSSL will quietly accept shorter byte counts, though it will reject longer ones.
        // This brings our behaviour into line with CryptoKit
        let group = Curve.group
        let length = bytes.withUnsafeBytes { $0.count }
        guard length == (group.coordinateByteCount * 3) + 1 else {
            throw CryptoKitError.incorrectParameterSize
        }

        self.key = try group.makeUnsafeOwnedECKey()

        // First, try to grab the numbers.
        var (x, y, k) = try bytes.readx963PrivateNumbers()

        // Then we set the private key first, then the public key. In this order, BoringSSL will check the key
        // validity for us.
        try self.setPrivateKey(k)
        try self.setPublicKey(x: &x, y: &y)
    }

    init<Bytes: ContiguousBytes>(rawRepresentation bytes: Bytes) throws {
        let group = Curve.group

        // Before we do anything, we validate that the raw representation has the right number of bytes.
        // This is because BoringSSL will quietly accept shorter byte counts, though it will reject longer ones.
        // This brings our behaviour into line with CryptoKit
        let length = bytes.withUnsafeBytes { $0.count }
        guard length == group.coordinateByteCount else {
            throw CryptoKitError.incorrectParameterSize
        }

        self.key = try group.makeUnsafeOwnedECKey()

        // The raw representation is just the bytes that make up k.
        let k = try ArbitraryPrecisionInteger(bytes: bytes)

        // Begin by setting the private key.
        try self.setPrivateKey(k)

        // Now calculate the public one and set it.
        let point = try EllipticCurvePoint(multiplying: k, on: group)
        try self.setPublicKey(point: point)
    }

    func setPrivateKey(_ keyScalar: ArbitraryPrecisionInteger) throws {
        try keyScalar.withUnsafeBignumPointer { bigNum in
            guard CCryptoBoringSSL_EC_KEY_set_private_key(self.key, bigNum) != 0 else {
                throw CryptoKitError.internalBoringSSLError()
            }
        }
    }

    func setPublicKey(x: inout ArbitraryPrecisionInteger, y: inout ArbitraryPrecisionInteger) throws {
        try x.withUnsafeMutableBignumPointer { xPointer in
            try y.withUnsafeMutableBignumPointer { yPointer in
                // This function is missing some const declarations here, which is why we need the bignums inout.
                // If that gets fixed, we can clean this function up.
                guard CCryptoBoringSSL_EC_KEY_set_public_key_affine_coordinates(self.key, xPointer, yPointer) != 0 else {
                    throw CryptoKitError.internalBoringSSLError()
                }
            }
        }
    }

    func setPublicKey(point: EllipticCurvePoint) throws {
        try point.withPointPointer { ecPointer in
            guard CCryptoBoringSSL_EC_KEY_set_public_key(self.key, ecPointer) != 0 else {
                throw CryptoKitError.internalBoringSSLError()
            }
        }
    }

    var publicKey: BoringSSLECPublicKeyWrapper<Curve> {
        // This is a weird little trick we can do here: because EC_KEY is both private and public depending on
        // its internal state, we can just vend a pointer to ourself and this will work.
        return try! BoringSSLECPublicKeyWrapper(unsafeTakingOwnership: CCryptoBoringSSL_EC_KEY_dup(self.key))
    }

    @usableFromInline
    var publicKeyPoint: EllipticCurvePoint {
        return try! EllipticCurvePoint(copying: CCryptoBoringSSL_EC_KEY_get0_public_key(self.key)!, on: Curve.group)
    }

    @usableFromInline
    var privateKeyScalar: ArbitraryPrecisionInteger {
        return try! ArbitraryPrecisionInteger(copying: CCryptoBoringSSL_EC_KEY_get0_private_key(self.key)!)
    }

    @inlinable
    var rawRepresentation: Data {
        // The raw representation is just the bytes that make up k. This try! should only fire if we have internal
        // consistency errors.
        var bytes = Data()
        bytes.reserveCapacity(Curve.group.coordinateByteCount)
        try! bytes.append(bytesOf: self.privateKeyScalar, paddedToSize: Curve.group.coordinateByteCount)
        return bytes
    }

    @inlinable
    var x963Representation: Data {
        // The x9.63 private key format is a discriminator byte (0x4) concatenated with the X and Y points
        // of the public key, and the K value of the secret scalar. Let's load that in.
        let group = Curve.group
        let pointByteCount = group.coordinateByteCount
        let privateKey = self.privateKeyScalar
        let (x, y) = try! self.publicKeyPoint.affineCoordinates(group: group)

        var bytes = Data()
        bytes.reserveCapacity(1 + (group.coordinateByteCount * 3))

        // These try!s should only trigger in the case of internal consistency errors.
        bytes.append(0x4)
        try! bytes.append(bytesOf: x, paddedToSize: pointByteCount)
        try! bytes.append(bytesOf: y, paddedToSize: pointByteCount)
        try! bytes.append(bytesOf: privateKey, paddedToSize: pointByteCount)

        return bytes
    }

    func keyExchange(publicKey: BoringSSLECPublicKeyWrapper<Curve>) throws -> SecureBytes {
        let pubKeyPoint = publicKey.publicKeyPoint
        let outputSize = Curve.group.coordinateByteCount

        return try SecureBytes(unsafeUninitializedCapacity: outputSize) { secretPtr, secretSize in
            let rc = pubKeyPoint.withPointPointer { pointPtr in
                CCryptoBoringSSL_ECDH_compute_key(secretPtr.baseAddress, secretPtr.count, pointPtr, self.key, nil)
            }

            if rc == -1 {
                throw CryptoKitError.internalBoringSSLError()
            }
            precondition(rc == outputSize, "Unexpectedly short secret.")
            secretSize = Int(rc)
        }
    }

    func sign<D: Digest>(digest: D) throws -> ECDSASignature {
        let optionalRawSignature: UnsafeMutablePointer<ECDSA_SIG>? = digest.withUnsafeBytes { digestPtr in
            CCryptoBoringSSLShims_ECDSA_do_sign(digestPtr.baseAddress, digestPtr.count, self.key)
        }
        guard let rawSignature = optionalRawSignature else {
            throw CryptoKitError.internalBoringSSLError()
        }

        return ECDSASignature(takingOwnershipOf: rawSignature)
    }

    deinit {
        CCryptoBoringSSL_EC_KEY_free(self.key)
    }
}

/// A simple wrapper for an EC_KEY pointer for a public key. This manages the lifetime of that pointer and
/// allows some helper operations.
@usableFromInline
class BoringSSLECPublicKeyWrapper<Curve: OpenSSLSupportedNISTCurve> {
    @usableFromInline
    var key: OpaquePointer

    init<Bytes: ContiguousBytes>(compactRepresentation bytes: Bytes) throws {
        let group = Curve.group

        // Before we do anything, we validate that the compact representation has the right number of bytes.
        // This is because BoringSSL will quietly accept shorter byte counts, though it will reject longer ones.
        // This brings our behaviour into line with CryptoKit
        let length = bytes.withUnsafeBytes { $0.count }
        guard length == group.coordinateByteCount else {
            throw CryptoKitError.incorrectParameterSize
        }

        self.key = try group.makeUnsafeOwnedECKey()

        // The compact representation is simply the X coordinate: deserializing then requires us to do a little math,
        // as discussed in https://tools.ietf.org/id/draft-jivsov-ecc-compact-05.html#rfc.section.4.1.
        var x = try ArbitraryPrecisionInteger(bytes: bytes)

        // We now need to solve the curve equation in Weierstrass form. This form is y² = x³ + ax + b. We need a and b.
        // We also need a finite field context, which means we need the order of the underlying prime field. We call that
        // p, for later.
        let (p, a, b) = group.weierstrassCoefficients
        let context = try FiniteFieldArithmeticContext(fieldSize: p)
        let xCubed = try (context.multiply(context.square(x), x))
        let ax = try context.multiply(a, x)
        let ySquared = try context.add(context.add(xCubed, ax), b)

        // We want the positive square root value of y, which conveniently is what we can get. We will call this yPrime.
        // We then need to calculate y = min(yPrime, p-yPrime) where p is the order of the underlying finite field.
        let yPrime = try context.positiveSquareRoot(ySquared)
        var y = min(yPrime, try context.subtract(yPrime, from: p))

        // This is the full set of coordinates. We're done.
        try self.setPublicKey(x: &x, y: &y)
    }

    init<Bytes: ContiguousBytes>(x963Representation bytes: Bytes) throws {
        // Before we do anything, we validate that the x963 representation has the right number of bytes.
        // This is because BoringSSL will quietly accept shorter byte counts, though it will reject longer ones.
        // This brings our behaviour into line with CryptoKit
        let group = Curve.group
        let length = bytes.withUnsafeBytes { $0.count }
        guard length == (group.coordinateByteCount * 2) + 1 else {
            throw CryptoKitError.incorrectParameterSize
        }

        self.key = try group.makeUnsafeOwnedECKey()
        var (x, y) = try bytes.readx963PublicNumbers()
        try self.setPublicKey(x: &x, y: &y)
    }

    init<Bytes: ContiguousBytes>(rawRepresentation bytes: Bytes) throws {
        let group = Curve.group

        // Before we do anything, we validate that the raw representation has the right number of bytes.
        // This is because BoringSSL will quietly accept shorter byte counts, though it will reject longer ones.
        // This brings our behaviour into line with CryptoKit
        let length = bytes.withUnsafeBytes { $0.count }
        guard length == group.coordinateByteCount * 2 else {
            throw CryptoKitError.incorrectParameterSize
        }

        self.key = try group.makeUnsafeOwnedECKey()

        // The raw representation is identical to the x963 representation, without the leading 0x4.
        var (x, y): (ArbitraryPrecisionInteger, ArbitraryPrecisionInteger) = try bytes.withUnsafeBytes { bytesPtr in
            try readRawPublicNumbers(copyingBytes: bytesPtr)
        }

        // Then we set the public key and we're done.
        try self.setPublicKey(x: &x, y: &y)
    }

    /// Takes ownership of the pointer. If this throws, ownership of the pointer has not been taken.
    @usableFromInline
    init(unsafeTakingOwnership ownedPointer: OpaquePointer) throws {
        guard let newKeyGroup = CCryptoBoringSSL_EC_KEY_get0_group(ownedPointer) else {
            throw CryptoKitError.internalBoringSSLError()
        }
        let groupEqual = Curve.group.withUnsafeGroupPointer { ourCurvePointer in
            CCryptoBoringSSL_EC_GROUP_cmp(newKeyGroup, ourCurvePointer, nil)
        }
        guard groupEqual == 0 else {
            throw CryptoKitError.incorrectParameterSize
        }

        self.key = ownedPointer
    }

    @inlinable
    var compactRepresentation: Data? {
        let group = Curve.group
        guard _isCompactRepresentable(group: group, publicKeyPoint: self.publicKeyPoint) else {
            return nil
        }

        // The compact representation is simply the X coordinate. This try! should only fire on internal consistency
        // errors.
        var bytes = Data()
        bytes.reserveCapacity(group.coordinateByteCount)

        let (x, _) = try! self.publicKeyPoint.affineCoordinates(group: group)
        try! bytes.append(bytesOf: x, paddedToSize: group.coordinateByteCount)
        return bytes
    }

    @inlinable
    var rawRepresentation: Data {
        // The raw representation is the X coordinate concatenated with the Y coordinate: essentially, it's
        // the x963 representation without the leading byte.
        return self.x963Representation.dropFirst()
    }

    @inlinable
    var x963Representation: Data {
        // The x963 representation is the X coordinate concatenated with the Y coordinate, prefixed by the byte 0x04.
        let group = Curve.group
        let (x, y) = try! self.publicKeyPoint.affineCoordinates(group: group)
        let pointByteCount = group.coordinateByteCount

        var bytes = Data()
        bytes.reserveCapacity(1 + (group.coordinateByteCount * 2))

        // These try!s should only trigger on internal consistency errors.
        bytes.append(0x4)
        try! bytes.append(bytesOf: x, paddedToSize: pointByteCount)
        try! bytes.append(bytesOf: y, paddedToSize: pointByteCount)

        return bytes
    }

    deinit {
        CCryptoBoringSSL_EC_KEY_free(self.key)
    }

    @usableFromInline
    var publicKeyPoint: EllipticCurvePoint {
        return try! EllipticCurvePoint(copying: CCryptoBoringSSL_EC_KEY_get0_public_key(self.key)!, on: Curve.group)
    }

    func setPublicKey(x: inout ArbitraryPrecisionInteger, y: inout ArbitraryPrecisionInteger) throws {
        try x.withUnsafeMutableBignumPointer { xPointer in
            try y.withUnsafeMutableBignumPointer { yPointer in
                // This function is missing some const declarations here, which is why we need the bignums inout.
                // If that gets fixed, we can clean this function up.
                guard CCryptoBoringSSL_EC_KEY_set_public_key_affine_coordinates(self.key, xPointer, yPointer) != 0 else {
                    throw CryptoKitError.internalBoringSSLError()
                }
            }
        }
    }

    func isValidSignature<D: Digest>(_ signature: ECDSASignature, for digest: D) -> Bool {
        let rc: CInt = signature.withUnsafeSignaturePointer { signaturePointer in
            digest.withUnsafeBytes { digestPointer in
                CCryptoBoringSSLShims_ECDSA_do_verify(digestPointer.baseAddress, digestPointer.count, signaturePointer, self.key)
            }
        }

        return rc == 1
    }
}

extension ContiguousBytes {
    func readx963PrivateNumbers() throws -> (x: ArbitraryPrecisionInteger, y: ArbitraryPrecisionInteger, k: ArbitraryPrecisionInteger) {
        // The x9.63 private key format is a discriminator byte (0x4) concatenated with the X and Y points
        // of the public key, and the K value of the secret scalar. Let's load that in.
        return try self.withUnsafeBytes { bytesPtr in
            guard bytesPtr.first == 0x04 else {
                throw CryptoKitError.incorrectKeySize // This is the same error CryptoKit throws on Apple platforms.
            }

            let stride = (bytesPtr.count - 1) / 3
            var offset = 1
            let xPointer = UnsafeRawBufferPointer(rebasing: bytesPtr[offset ..< (offset + stride)])
            offset += stride
            let yPointer = UnsafeRawBufferPointer(rebasing: bytesPtr[offset ..< (offset + stride)])
            offset += stride
            let kPointer = UnsafeRawBufferPointer(rebasing: bytesPtr[offset ..< (offset + stride)])

            let x = try ArbitraryPrecisionInteger(bytes: xPointer)
            let y = try ArbitraryPrecisionInteger(bytes: yPointer)
            let k = try ArbitraryPrecisionInteger(bytes: kPointer)

            return (x: x, y: y, k: k)
        }
    }

    @inlinable
    func readx963PublicNumbers() throws -> (x: ArbitraryPrecisionInteger, y: ArbitraryPrecisionInteger) {
        // The x9.63 public key format is a discriminator byte (0x4) concatenated with the X and Y points
        // of the public key. Let's load that in.
        return try self.withUnsafeBytes { bytesPtr in
            guard bytesPtr.first == 0x04 else {
                throw CryptoKitError.incorrectKeySize // This is the same error CryptoKit throws on Apple platforms.
            }

            return try readRawPublicNumbers(copyingBytes: UnsafeRawBufferPointer(rebasing: bytesPtr[1...]))
        }
    }
}

@usableFromInline
func readRawPublicNumbers(copyingBytes bytesPtr: UnsafeRawBufferPointer) throws -> (x: ArbitraryPrecisionInteger, y: ArbitraryPrecisionInteger) {
    let stride = bytesPtr.count / 2
    var offset = 0
    let xPointer = UnsafeRawBufferPointer(rebasing: bytesPtr[offset ..< (offset + stride)])
    offset += stride
    let yPointer = UnsafeRawBufferPointer(rebasing: bytesPtr[offset ..< (offset + stride)])

    // We cannot handle allocation errors, so we check for fatal error.
    let x = try ArbitraryPrecisionInteger(bytes: xPointer)
    let y = try ArbitraryPrecisionInteger(bytes: yPointer)

    return (x: x, y: y)
}

/// In a number of places we need to know if an EC key is compact representable. This function implements that check.
///
/// The check is defined in https://tools.ietf.org/id/draft-jivsov-ecc-compact-05.html#rfc.section.4.2.1. Specifically, a
/// point is compact representable if its y coordinate is the smaller of min(y, p-y) where p is the order of the prime field.
@usableFromInline
func _isCompactRepresentable(group: BoringSSLEllipticCurveGroup, publicKeyPoint: EllipticCurvePoint) -> Bool {
    // We have three try!s here: any of those failing is the result of an allocation error, and we cannot recover from
    // those.
    let (_, y) = try! publicKeyPoint.affineCoordinates(group: group)
    let p = group.weierstrassCoefficients.field
    let context = try! FiniteFieldArithmeticContext(fieldSize: p)
    let newY = try! context.subtract(y, from: group.order)

    // The point is compact representable if y is less than or equal to newY.
    return y <= newY
}
#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
