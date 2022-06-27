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
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
import Foundation

extension ASN1 {
    struct GeneralizedTime: ASN1ImplicitlyTaggable, Hashable {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .generalizedTime
        }

        var year: Int {
            get {
                return self._year
            }
            set {
                self._year = newValue
                try! self.validate()
            }
        }

        var month: Int {
            get {
                return self._month
            }
            set {
                self._month = newValue
                try! self.validate()
            }
        }

        var day: Int {
            get {
                return self._day
            }
            set {
                self._day = newValue
                try! self.validate()
            }
        }

        var hours: Int {
            get {
                return self._hours
            }
            set {
                self._hours = newValue
                try! self.validate()
            }
        }

        var minutes: Int {
            get {
                return self._minutes
            }
            set {
                self._minutes = newValue
                try! self.validate()
            }
        }

        var seconds: Int {
            get {
                return self._seconds
            }
            set {
                self._seconds = newValue
                try! self.validate()
            }
        }

        var fractionalSeconds: Double {
            get {
                return self._fractionalSeconds
            }
            set {
                self._fractionalSeconds = newValue
                try! self.validate()
            }
        }

        private var _year: Int
        private var _month: Int
        private var _day: Int
        private var _hours: Int
        private var _minutes: Int
        private var _seconds: Int
        private var _fractionalSeconds: Double

        init(year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int, fractionalSeconds: Double) throws {
            self._year = year
            self._month = month
            self._day = day
            self._hours = hours
            self._minutes = minutes
            self._seconds = seconds
            self._fractionalSeconds = fractionalSeconds

            try self.validate()
        }

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            guard node.identifier == identifier else {
                throw CryptoKitASN1Error.unexpectedFieldType
            }

            guard case .primitive(let content) = node.content else {
                preconditionFailure("ASN.1 parser generated primitive node with constructed content")
            }

            self = try .parseDateBytes(content)
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            coder.appendPrimitiveNode(identifier: identifier) { bytes in
                bytes.append(self)
            }
        }

        private func validate() throws {
            // Validate that the structure is well-formed.
            guard self._year >= 0 && self._year <= 9999 else {
                throw CryptoKitASN1Error.invalidASN1Object
            }

            // This also validates the month.
            guard let daysInMonth = ASN1.GeneralizedTime.daysInMonth(self._month, ofYear: self._year) else {
                throw CryptoKitASN1Error.invalidASN1Object
            }

            guard self._day >= 1 && self._day <= daysInMonth else {
                throw CryptoKitASN1Error.invalidASN1Object
            }

            guard self._hours >= 0 && self._hours < 24 else {
                throw CryptoKitASN1Error.invalidASN1Object
            }

            guard self._minutes >= 0 && self._minutes < 60 else {
                throw CryptoKitASN1Error.invalidASN1Object
            }

            // We allow leap seconds here, but don't validate it.
            // This exposes us to potential confusion if we naively implement
            // comparison here. We should consider whether this needs to be transformable
            // to `Date` or similar.
            guard self._seconds >= 0 && self._seconds <= 61 else {
                throw CryptoKitASN1Error.invalidASN1Object
            }

            // Fractional seconds may not be negative and may not be 1 or more.
            guard self._fractionalSeconds >= 0 && self._fractionalSeconds < 1 else {
                throw CryptoKitASN1Error.invalidASN1Object
            }
        }
    }
}

extension ASN1.GeneralizedTime {
    fileprivate static func parseDateBytes(_ bytes: ArraySlice<UInt8>) throws -> ASN1.GeneralizedTime {
        var bytes = bytes

        // First, there must always be a calendar date. No separators, 4
        // digits for the year, 2 digits for the month, 2 digits for the day.
        guard let rawYear = bytes.readFourDigitDecimalInteger(),
              let rawMonth = bytes.readTwoDigitDecimalInteger(),
              let rawDay = bytes.readTwoDigitDecimalInteger() else {
            throw CryptoKitASN1Error.invalidASN1Object
        }

        // Next there must be a _time_. Per DER rules, this time must always go
        // to at least seconds, there are no separators, there is no time-zone (but there must be a 'Z'),
        // and there may be fractional seconds but they must not have trailing zeros.
        guard let rawHour = bytes.readTwoDigitDecimalInteger(),
              let rawMinutes = bytes.readTwoDigitDecimalInteger(),
              let rawSeconds = bytes.readTwoDigitDecimalInteger() else {
            throw CryptoKitASN1Error.invalidASN1Object
        }

        // There may be some fractional seconds.
        var fractionalSeconds: Double = 0
        if bytes.first == UInt8(ascii: ".") {
            fractionalSeconds = try bytes.readFractionalSeconds()
        }

        // The next character _must_ be Z, or the encoding is invalid.
        guard bytes.popFirst() == UInt8(ascii: "Z") else {
            throw CryptoKitASN1Error.invalidASN1Object
        }

        // Great! There better not be anything left.
        guard bytes.count == 0 else {
            throw CryptoKitASN1Error.invalidASN1Object
        }

        return try ASN1.GeneralizedTime(year: rawYear,
                                        month: rawMonth,
                                        day: rawDay,
                                        hours: rawHour,
                                        minutes: rawMinutes,
                                        seconds: rawSeconds,
                                        fractionalSeconds: fractionalSeconds)
    }

    static func daysInMonth(_ month: Int, ofYear year: Int) -> Int? {
        switch month {
        case 1:
            return 31
        case 2:
            // This one has a dependency on the year!
            // A leap year occurs in any year divisible by 4, except when that year is divisible by 100,
            // unless the year is divisible by 400.
            let isLeapYear = (year % 4 == 0) && ((year % 100 != 0) || (year % 400 == 0))
            return isLeapYear ? 29 : 28
        case 3:
            return 31
        case 4:
            return 30
        case 5:
            return 31
        case 6:
            return 30
        case 7:
            return 31
        case 8:
            return 31
        case 9:
            return 30
        case 10:
            return 31
        case 11:
            return 30
        case 12:
            return 31
        default:
            return nil
        }
    }
}

extension ArraySlice where Element == UInt8 {
    fileprivate mutating func readFourDigitDecimalInteger() -> Int? {
        guard let first = self.readTwoDigitDecimalInteger(),
              let second = self.readTwoDigitDecimalInteger() else {
            return nil
        }

        // Unchecked math is still safe here: we're in Int32 space, and this number cannot
        // get any larger than 9999.
        return (first &* 100) &+ second
    }

    fileprivate mutating func readTwoDigitDecimalInteger() -> Int? {
        guard let firstASCII = self.popFirst(),
              let secondASCII = self.popFirst() else {
            return nil
        }

        guard let first = Int(fromDecimalASCII: firstASCII),
              let second = Int(fromDecimalASCII: secondASCII) else {
            return nil
        }

        // Unchecked math is safe here: we're in Int32 space at the very least, and this number cannot
        // possibly be smaller than zero or larger than 99.
        return (first &* 10) &+ (second)
    }

    /// This may only be called if there's a leading period: we precondition on this fact.
    fileprivate mutating func readFractionalSeconds() throws -> Double {
        precondition(self.popFirst() == UInt8(ascii: "."))

        var numerator = 0
        var denominator = 1

        while let nextASCII = self.first, let next = Int(fromDecimalASCII: nextASCII) {
            self = self.dropFirst()

            let (newNumerator, multiplyOverflow) = numerator.multipliedReportingOverflow(by: 10)
            let (newDenominator, secondMultiplyOverflow) = denominator.multipliedReportingOverflow(by: 10)
            let (newNumeratorWithAdded, addingOverflow) = newNumerator.addingReportingOverflow(next)

            // If the new denominator overflows, we just cap to the old value.
            if !secondMultiplyOverflow {
                denominator = newDenominator
            }

            // If the numerator overflows, we don't support the result.
            if multiplyOverflow || addingOverflow {
                throw CryptoKitASN1Error.invalidASN1Object
            }

            numerator = newNumeratorWithAdded
        }

        // Ok, we're either at the end or the next character is a Z. One final check: there may not have
        // been any trailing zeros here. This means the number may not be 0 mod 10.
        if numerator % 10 == 0 {
            throw CryptoKitASN1Error.invalidASN1Object
        }

        return Double(numerator) / Double(denominator)
    }
}

extension Array where Element == UInt8 {
    fileprivate mutating func append(_ generalizedTime: ASN1.GeneralizedTime) {
        self.appendFourDigitDecimal(generalizedTime.year)
        self.appendTwoDigitDecimal(generalizedTime.month)
        self.appendTwoDigitDecimal(generalizedTime.day)
        self.appendTwoDigitDecimal(generalizedTime.hours)
        self.appendTwoDigitDecimal(generalizedTime.minutes)
        self.appendTwoDigitDecimal(generalizedTime.seconds)

        // Ok, tricky moment here. Is the fractional part non-zero? If it is, we need to write it out as well.
        if generalizedTime.fractionalSeconds != 0 {
            let stringified = String(generalizedTime.fractionalSeconds)
            assert(stringified.starts(with: "0."))

            self.append(contentsOf: stringified.utf8.dropFirst(1))
            // Remove any trailing zeros from self, they are forbidden.
            while self.last == 0 {
                self = self.dropLast()
            }
        }

        self.append(UInt8(ascii: "Z"))
    }

    fileprivate mutating func appendFourDigitDecimal(_ number: Int) {
        assert(number >= 0 && number <= 9999)

        // Each digit can be isolated by dividing by the place and then taking the result modulo 10.
        // This is annoyingly division heavy. There may be a better algorithm floating around.
        // Unchecked math is fine, there cannot be an overflow here.
        let asciiZero = UInt8(ascii: "0")
        self.append(UInt8(truncatingIfNeeded: (number / 1000) % 10) &+ asciiZero)
        self.append(UInt8(truncatingIfNeeded: (number / 100) % 10) &+ asciiZero)
        self.append(UInt8(truncatingIfNeeded: (number / 10) % 10) &+ asciiZero)
        self.append(UInt8(truncatingIfNeeded: number % 10) &+ asciiZero)
    }

    fileprivate mutating func appendTwoDigitDecimal(_ number: Int) {
        assert(number >= 0 && number <= 99)

        // Each digit can be isolated by dividing by the place and then taking the result modulo 10.
        // This is annoyingly division heavy. There may be a better algorithm floating around.
        // Unchecked math is fine, there cannot be an overflow here.
        let asciiZero = UInt8(ascii: "0")
        self.append(UInt8(truncatingIfNeeded: (number / 10) % 10) &+ asciiZero)
        self.append(UInt8(truncatingIfNeeded: number % 10) &+ asciiZero)
    }
}

extension Int {
    fileprivate init?(fromDecimalASCII ascii: UInt8) {
        let asciiZero = UInt8(ascii: "0")
        let zeroToNine = 0...9

        // These are all coming from UInt8space, the subtraction cannot overflow.
        let converted = Int(ascii) &- Int(asciiZero)

        guard zeroToNine.contains(converted) else {
            return nil
        }

        self = converted
    }
}

#endif // Linux or !SwiftPM
