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
nonisolated(unsafe) private let emptyStorage:SecureBytes.Backing = SecureBytes.Backing.createEmpty()

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct SecureBytes: @unchecked Sendable {
    var backing: Backing

    init() {
        self = .init(count: 0)
    }

    init(count: Int) {
        if count == 0 {
            self.backing = emptyStorage
        } else {
            self.backing = SecureBytes.Backing.create(randomBytes: count)
        }
    }

    init<D: ContiguousBytes>(bytes: D) {
        self.backing = Backing.create(bytes: bytes)
    }

    /// Allows initializing a SecureBytes object with a closure that will initialize the memory.
    #if hasFeature(Embedded)
    init<E: Error>(unsafeUninitializedCapacity: Int, initializingWith callback: (inout UnsafeMutableRawBufferPointer, inout Int) throws(E) -> Void) throws(E) {
        self.backing = Backing.create(capacity: unsafeUninitializedCapacity)
        try self.backing._withVeryUnsafeMutableBytes { veryUnsafePointer throws(E) in
            // As Array does, we want to truncate the initializing pointer to only have the requested size.
            var veryUnsafePointer = UnsafeMutableRawBufferPointer(rebasing: veryUnsafePointer.prefix(unsafeUninitializedCapacity))
            var initializedCount = 0
            try callback(&veryUnsafePointer, &initializedCount)

            self.backing.count = initializedCount
        }
    }
    #else
    init(unsafeUninitializedCapacity: Int, initializingWith callback: (inout UnsafeMutableRawBufferPointer, inout Int) throws -> Void) rethrows {
        self.backing = Backing.create(capacity: unsafeUninitializedCapacity)
        try self.backing._withVeryUnsafeMutableBytes { veryUnsafePointer in
            // As Array does, we want to truncate the initializing pointer to only have the requested size.
            var veryUnsafePointer = UnsafeMutableRawBufferPointer(rebasing: veryUnsafePointer.prefix(unsafeUninitializedCapacity))
            var initializedCount = 0
            try callback(&veryUnsafePointer, &initializedCount)

            self.backing.count = initializedCount
        }
    }
    #endif
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes {
    mutating func append<C: Collection>(_ data: C) where C.Element == UInt8 {
        let requiredCapacity = self.count + data.count
        let backingCapacity = self.backing.allocatedCapacity
        if !isKnownUniquelyReferenced(&self.backing) || requiredCapacity > backingCapacity {
            let newBacking = Backing.create(capacity: requiredCapacity)
            newBacking._appendBytes(self.backing, inRange: 0..<self.count)
            self.backing = newBacking
        }
        self.backing._appendBytes(data)
    }

    mutating func reserveCapacity(_ n: Int) {
        let backingCapacity = self.backing.allocatedCapacity
        if backingCapacity >= n {
            return
        }

        let newBacking = Backing.create(capacity: n)
        newBacking._appendBytes(self.backing, inRange: 0..<self.count)
        self.backing = newBacking
    }
}

// MARK: - Equatable conformance, constant-time
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes: Equatable {
    public static func == (lhs: SecureBytes, rhs: SecureBytes) -> Bool {
        return safeCompare(lhs, rhs)
    }
}

// MARK: - Collection conformance
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes: Collection {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    struct Index {
        fileprivate var offset: Int

        internal init(offset: Int) {
            self.offset = offset
        }
    }

    var startIndex: Index {
        return Index(offset: 0)
    }

    var endIndex: Index {
        return Index(offset: self.count)
    }

    var count: Int {
        return self.backing.count
    }

    subscript(_ index: Index) -> UInt8 {
        get {
            return self.backing[offset: index.offset]
        }
        set {
            self.backing[offset: index.offset] = newValue
        }
    }

    func index(after index: Index) -> Index {
        return index.advanced(by: 1)
    }
}

// MARK: - BidirectionalCollection conformance
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes: BidirectionalCollection {
    func index(before index: Index) -> Index {
        return index.advanced(by: -1)
    }
}

// MARK: - RandomAccessCollection conformance
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes: RandomAccessCollection { }

// MARK: - MutableCollection conformance
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes: MutableCollection { }

// MARK: - RangeReplaceableCollection conformance
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes: RangeReplaceableCollection {
    mutating func replaceSubrange<C: Collection>(_ subrange: Range<Index>, with newElements: C) where C.Element == UInt8 {
        let requiredCapacity = self.backing.count - subrange.count + newElements.count
        let backingCapacity = self.backing.allocatedCapacity

        if !isKnownUniquelyReferenced(&self.backing) || requiredCapacity > backingCapacity {
            // We have to allocate anyway, so let's use a nice straightforward copy.
            let newBacking = Backing.create(capacity: requiredCapacity)

            let lowerSlice = 0..<subrange.lowerBound.offset
            let upperSlice = subrange.upperBound.offset..<self.count

            newBacking._appendBytes(self.backing, inRange: lowerSlice)
            newBacking._appendBytes(newElements)
            newBacking._appendBytes(self.backing, inRange: upperSlice)

            self.backing = newBacking
            return
        } else {
            // We have room, and a unique pointer. Ask the backing storage to shuffle around.
            let offsetRange = subrange.lowerBound.offset..<subrange.upperBound.offset
            self.backing.replaceSubrangeFittingWithinCapacity(offsetRange, with: newElements)
        }
    }

    // The default implementation of this from RangeReplaceableCollection can't take advantage of `ContiguousBytes`, so we override it here
    mutating func append(contentsOf newElements: some Sequence<UInt8>) {
        let done:Void? = newElements.withContiguousStorageIfAvailable {
            replaceSubrange(endIndex..<endIndex, with: $0)
        }
        
        if done == nil {
            for element in newElements {
                append(element)
            }
        }
    }
}

// MARK: - ContiguousBytes conformance
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes: ContiguousBytes {
    #if hasFeature(Embedded)
    func withUnsafeBytes<T, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> T) throws(E) -> T {
        return try self.backing.withUnsafeBytes(body)
    }
    #else
    func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        return try self.backing.withUnsafeBytes(body)
    }
    #endif

    #if hasFeature(Embedded)
    mutating func withUnsafeMutableBytes<T, E: Error>(_ body: (UnsafeMutableRawBufferPointer) throws(E) -> T) throws(E) -> T {
        if !isKnownUniquelyReferenced(&self.backing) {
            self.backing = Backing.create(copying: self.backing)
        }

        return try self.backing.withUnsafeMutableBytes(body)
    }
    #else
    mutating func withUnsafeMutableBytes<T>(_ body: (UnsafeMutableRawBufferPointer) throws -> T) rethrows -> T {
        if !isKnownUniquelyReferenced(&self.backing) {
            self.backing = Backing.create(copying: self.backing)
        }

        return try self.backing.withUnsafeMutableBytes(body)
    }
    #endif

    #if hasFeature(Embedded)
    func withContiguousStorageIfAvailable<R, E: Error>(_ body: (UnsafeBufferPointer<UInt8>) throws(E) -> R) throws(E) -> R? {
        return try self.backing.withContiguousStorageIfAvailable(body)
    }
    #else
    func withContiguousStorageIfAvailable<R>(_ body: (UnsafeBufferPointer<UInt8>) throws -> R) rethrows -> R? {
        return try self.backing.withContiguousStorageIfAvailable(body)
    }
    #endif
}

// MARK: - DataProtocol conformance
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes: DataProtocol {
    var regions: CollectionOfOne<SecureBytes> {
        return CollectionOfOne(self)
    }
}

// MARK: - MutableDataProtocol conformance
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes: MutableDataProtocol { }

// MARK: - Index conformances
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes.Index: Hashable { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes.Index: Comparable {
    static func <(lhs: SecureBytes.Index, rhs: SecureBytes.Index) -> Bool {
        return lhs.offset < rhs.offset
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes.Index: Strideable {
    func advanced(by n: Int) -> SecureBytes.Index {
        return SecureBytes.Index(offset: self.offset + n)
    }

    func distance(to other: SecureBytes.Index) -> Int {
        return other.offset - self.offset
    }
}

// MARK: - Heap allocated backing storage.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes {
#if !hasFeature(Embedded)
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    internal struct BackingHeader {
        internal var count: Int

        internal var capacity: Int
    }

    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    internal class Backing: ManagedBuffer<BackingHeader, UInt8> {

        class func createEmpty() -> Backing {
            return Backing.create(minimumCapacity: 0, makingHeaderWith: { _ in BackingHeader(count: 0, capacity: 0) }) as! Backing
        }

        class func create(capacity: Int) -> Backing {
            let capacity = Int(UInt32(capacity).nextPowerOf2ClampedToMax())
            return Backing.create(minimumCapacity: capacity, makingHeaderWith: { _ in BackingHeader(count: 0, capacity: capacity) }) as! Backing
        }

        class func create(copying original: Backing) -> Backing {
            return Backing.create(bytes: original)
        }

        final class func create<D: ContiguousBytes>(bytes: D) -> Backing {
            return bytes.withUnsafeBytes { bytesPtr in
                let backing = Backing.create(capacity: bytesPtr.count)
                backing._withVeryUnsafeMutableBytes { targetPtr in
                    targetPtr.copyMemory(from: bytesPtr)
                }
                backing.count = bytesPtr.count
                precondition(backing.count <= backing.allocatedCapacity)
                return backing
            }
        }

        class func create(randomBytes: Int) -> Backing {
            let backing = Backing.create(capacity: randomBytes)
            backing._withVeryUnsafeMutableBytes { targetPtr in
                assert(targetPtr.count >= randomBytes)
                targetPtr.initializeWithRandomBytes(count: randomBytes)
            }
            backing.count = randomBytes
            return backing
        }

        deinit {
            // We always clear the whole capacity, even if we don't think we used it all.
            let bytesToClear = self.header.capacity

            _ = self.withUnsafeMutablePointerToElements { elementsPtr in
                memset_s(elementsPtr, bytesToClear, 0, bytesToClear)
            }
        }

        var count: Int {
            get {
                return self.header.count
            }
            set {
                self.header.count = newValue
            }
        }

        subscript(offset offset: Int) -> UInt8 {
            get {
                // precondition(offset >= 0 && offset < self.count)
                return self.withUnsafeMutablePointerToElements { return ($0 + offset).pointee }
            }
            set {
                // precondition(offset >= 0 && offset < self.count)
                return self.withUnsafeMutablePointerToElements { ($0 + offset).pointee = newValue }
            }
        }
    }
#else
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    internal class Backing {
        private var storage: UnsafeMutableRawBufferPointer

        var count: Int
        var capacity: Int {
            storage.count
        }

        private init(storage: UnsafeMutableRawBufferPointer, count: Int) {
            self.storage = storage
            self.count = count
        }

        class func createEmpty() -> Backing {
            return Backing.create(capacity: 0)
        }

        class func create(capacity: Int) -> Backing {
            let capacity = Int(UInt32(capacity).nextPowerOf2ClampedToMax())
            let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: capacity, alignment: Int(CC_MAX_ALIGNMENT))
            return Backing.init(storage: buffer, count: 0)
        }

        class func create(copying original: Backing) -> Backing {
            let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: original.capacity, alignment: Int(CC_MAX_ALIGNMENT))
            buffer.copyBytes(from: original.storage)
            return Backing.init(storage: buffer, count: original.count)
        }

        final class func create<D: ContiguousBytes>(bytes: D) -> Backing {
            return bytes.withUnsafeBytes { bytesPtr in
                let backing = Backing.create(capacity: bytesPtr.count)
                backing._withVeryUnsafeMutableBytes { targetPtr in
                    targetPtr.copyMemory(from: bytesPtr)
                }
                backing.count = bytesPtr.count
                precondition(backing.count <= backing.capacity)
                return backing
            }
        }

        class func create(randomBytes: Int) -> Backing {
            let backing = Backing.create(capacity: randomBytes)
            backing._withVeryUnsafeMutableBytes { targetPtr in
                assert(targetPtr.count >= randomBytes)
                targetPtr.initializeWithRandomBytes(count: randomBytes)
            }
            backing.count = randomBytes
            return backing
        }

        deinit {
            // We always clear the whole capacity, even if we don't think we used it all.
            memset_s(storage.baseAddress, storage.count, 0, storage.count)
        }

        subscript(offset offset: Int) -> UInt8 {
            get {
                // precondition(offset >= 0 && offset < self.count)
                return storage[offset]
            }
            set {
                // precondition(offset >= 0 && offset < self.count)
                storage[offset] = newValue
            }
        }
    }
#endif
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes.Backing {
    var allocatedCapacity: Int {
#if os(OpenBSD)
        return self.header.capacity
#else
        return self.capacity
#endif
    }

    func replaceSubrangeFittingWithinCapacity<C: Collection>(_ subrange: Range<Int>, with newElements: C) where C.Element == UInt8 {
        // This function is called when have a unique reference to the backing storage, and we have enough room to store these bytes without
        // any problem. We have one pre-existing buffer made up of 4 regions: a prefix set of bytes that are
        // before the range "subrange", a range of bytes to be replaced (R1), a suffix set of bytes that are after
        // the range "subrange" but within the valid count, and then a region of uninitialized memory. We also have
        // a new set of bytes, R2, that may be larger or smaller than R1, and could indeed be empty!
        //
        // ┌────────────────────────┬──────────────────┬──────────────────┬───────────────┐
        // │         Prefix         │        R1        │      Suffix      │ Uninitialized │
        // └────────────────────────┴──────────────────┴──────────────────┴───────────────┘
        //
        //                ┌─────────────────────────────────────┐
        //                │                  R2                 │
        //                └─────────────────────────────────────┘
        //
        // The minimal number of steps we can take in the general case is two steps. We can't just copy R2 into the space
        // for R1 and then move the suffix, as if R2 is larger than R1 we'll have thrown some suffix bytes away. So we have
        // to move suffix first. What we do is take the bytes in suffix, and move them (via memmove). We can then copy
        // R2 in, and feel confident that the space in memory is right.
        precondition(self.count - subrange.count + newElements.count <= self.allocatedCapacity, "Insufficient capacity")

        let moveDistance = newElements.count - subrange.count
        let suffixRange = subrange.upperBound..<self.count
        self._moveBytes(range: suffixRange, by: moveDistance)
        self._copyBytes(newElements, at: subrange.lowerBound)
        self.count += newElements.count - subrange.count
    }

    /// Appends the bytes of a collection to this storage, crashing if there is not enough room.
    fileprivate func _appendBytes<C: Collection>(_ bytes: C) where C.Element == UInt8 {
        let byteCount = bytes.count

        precondition(self.allocatedCapacity - self.count - byteCount >= 0, "Insufficient space for byte copying, must have reallocated!")

        let lowerOffset = self.count
        self._withVeryUnsafeMutableBytes { bytesPtr in
            let innerPtrSlice = UnsafeMutableRawBufferPointer(rebasing: bytesPtr[lowerOffset...])
            innerPtrSlice.copyBytes(from: bytes)
        }
        self.count += byteCount
    }

    /// Appends the bytes of a slice of another backing buffer to this storage, crashing if there
    /// is not enough room.
    fileprivate func _appendBytes(_ backing: SecureBytes.Backing, inRange range: Range<Int>) {
        precondition(range.lowerBound >= 0)
        precondition(range.upperBound <= backing.allocatedCapacity)
        precondition(self.allocatedCapacity - self.count - range.count >= 0, "Insufficient space for byte copying, must have reallocated!")

        backing.withUnsafeBytes { backingPtr in
            let ptrSlice = UnsafeRawBufferPointer(rebasing: backingPtr[range])

            let lowerOffset = self.count
            self._withVeryUnsafeMutableBytes { bytesPtr in
                let innerPtrSlice = UnsafeMutableRawBufferPointer(rebasing: bytesPtr[lowerOffset...])
                innerPtrSlice.copyMemory(from: ptrSlice)
            }
            self.count += ptrSlice.count
        }
    }

    /// Moves the range of bytes identified by the slice by the delta, crashing if the move would
    /// place the bytes out of the storage. Note that this does not update the count: external code
    /// must ensure that that happens.
    private func _moveBytes(range: Range<Int>, by delta: Int) {
        // We have to check that the range is within the delta, as is the new location.
        precondition(range.lowerBound >= 0)
        precondition(range.upperBound <= self.allocatedCapacity)

        let shiftedRange = (range.lowerBound + delta)..<(range.upperBound + delta)
        precondition(shiftedRange.lowerBound > 0)
        precondition(shiftedRange.upperBound <= self.allocatedCapacity)

        self._withVeryUnsafeMutableBytes { backingPtr in
            let source = UnsafeRawBufferPointer(rebasing: backingPtr[range])
            let dest = UnsafeMutableRawBufferPointer(rebasing: backingPtr[shiftedRange])
            dest.copyMemory(from: source)  // copy memory uses memmove under the hood.
        }
    }

    // Copies some bytes into the buffer at the appropriate place. Does not update count: external code must do so.
    private func _copyBytes<C: Collection>(_ bytes: C, at offset: Int) where C.Element == UInt8 {
        precondition(offset >= 0)
        precondition(offset + bytes.count <= self.allocatedCapacity)

        let byteRange = offset..<(offset + bytes.count)

        self._withVeryUnsafeMutableBytes { backingPtr in
            let dest = UnsafeMutableRawBufferPointer(rebasing: backingPtr[byteRange])
            dest.copyBytes(from: bytes)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SecureBytes.Backing: ContiguousBytes {
#if hasFeature(Embedded)
    func withUnsafeBytes<T, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> T) throws(E) -> T {
        let count = self.count
        return try storage.withUnsafeBytes { elementsPtr throws(E) in
            return try body(UnsafeRawBufferPointer(start: elementsPtr.baseAddress, count: count))
        }
    }
#else
    func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        let count = self.count
        return try self.withUnsafeMutablePointerToElements { elementsPtr in
            return try body(UnsafeRawBufferPointer(start: elementsPtr, count: count))
        }
    }
#endif

    #if hasFeature(Embedded)

    func withUnsafeMutableBytes<T, E: Error>(_ body: (UnsafeMutableRawBufferPointer) throws(E) -> T) throws(E) -> T {
        return try body(storage)
    }
    #else
    func withUnsafeMutableBytes<T>(_ body: (UnsafeMutableRawBufferPointer) throws -> T) rethrows -> T {
        let count = self.count

        return try self.withUnsafeMutablePointerToElements { elementsPtr in
            return try body(UnsafeMutableRawBufferPointer(start: elementsPtr, count: count))
        }
    }
    #endif

#if hasFeature(Embedded)
    /// Very unsafe in the sense that this points to uninitialized memory. Used only for implementations within this file.
    func _withVeryUnsafeMutableBytes<T, E: Error>(_ body: (UnsafeMutableRawBufferPointer) throws(E) -> T) throws(E) -> T {
        return try body(storage)
    }
#else
    /// Very unsafe in the sense that this points to uninitialized memory. Used only for implementations within this file.
    func _withVeryUnsafeMutableBytes<T>(_ body: (UnsafeMutableRawBufferPointer) throws -> T) rethrows -> T {
        let capacity = self.allocatedCapacity

        return try self.withUnsafeMutablePointerToElements { elementsPtr in
            return try body(UnsafeMutableRawBufferPointer(start: elementsPtr, count: capacity))
        }
    }
#endif

#if hasFeature(Embedded)
    func withContiguousStorageIfAvailable<R, E: Error>(_ body: (UnsafeBufferPointer<UInt8>) throws(E) -> R) throws(E) -> R? {
        let count = self.count
        return try storage.withUnsafeBytes { elementsPtr throws(E) -> R? in
            return try body(UnsafeBufferPointer(start: elementsPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), count: count))
        }
    }
#else
    func withContiguousStorageIfAvailable<R>(_ body: (UnsafeBufferPointer<UInt8>) throws -> R) rethrows -> R? {
        let count = self.count

        return try self.withUnsafeMutablePointerToElements { elementsPtr in
            return try body(UnsafeBufferPointer(start: elementsPtr, count: count))
        }
    }
#endif
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension UInt32 {
    /// Returns the next power of two unless that would overflow, in which case UInt32.max (on 64-bit systems) or
    /// Int32.max (on 32-bit systems) is returned. The returned value is always safe to be cast to Int and passed
    /// to malloc on all platforms.
    func nextPowerOf2ClampedToMax() -> UInt32 {
        guard self > 0 else {
            return 1
        }

        var n = self

        #if arch(arm) || arch(i386)
        // on 32-bit platforms we can't make use of a whole UInt32.max (as it doesn't fit in an Int)
        let max = UInt32(Int.max)
        #else
        // on 64-bit platforms we're good
        let max = UInt32.max
        #endif

        n -= 1
        n |= n >> 1
        n |= n >> 2
        n |= n >> 4
        n |= n >> 8
        n |= n >> 16
        if n != max {
            n += 1
        }

        return n
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Data {
    /// A custom initializer for Data that attempts to share the same storage as the current SecureBytes instance.
    /// This is our best-effort attempt to expose the data in an auto-zeroing fashion. Any mutating function called on
    /// the constructed `Data` object will cause the bytes to be copied out: we can't avoid that.
    init(_ secureBytes: SecureBytes) {
        #if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
        self = secureBytes.withUnsafeBytes {
            // We make a mutable copy of this pointer here because we know Data won't write through it.
            return Data($0)
        }
        #else
        // We need to escape into unmanaged land here in order to keep the backing storage alive.
        let unmanagedBacking = Unmanaged.passRetained(secureBytes.backing)

        // We can now exfiltrate the storage pointer: this particular layout will be locked forever. Please never do this
        // yourself unless you're really sure!
        self = secureBytes.withUnsafeBytes {
            // We make a mutable copy of this pointer here because we know Data won't write through it.
            return Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: $0.baseAddress!), count: $0.count, deallocator: .custom { (_: UnsafeMutableRawPointer, _: Int) in unmanagedBacking.release() })
        }
        #endif
    }

    /// A custom initializer for Data that attempts to share the same storage as the current SecureBytes instance.
    /// This is our best-effort attempt to expose the data in an auto-zeroing fashion. Any mutating function called on the
    /// constructed `Data` object will cause the bytes to be copied out: we can't avoid that.
    init(_ secureByteSlice: Slice<SecureBytes>) {
        // We have a trick here: we use the same function as the one above, but we use the indices of the slice to bind
        // the scope of the pointer we pass to Data.
        let base = secureByteSlice.base
        let baseOffset = secureByteSlice.startIndex.offset
        let endOffset = secureByteSlice.endIndex.offset
        
        #if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
        self = base.withUnsafeBytes {
            // Slice the base pointer down to just the range we want.
            let slicedPointer = UnsafeRawBufferPointer(rebasing: $0[baseOffset..<endOffset])

            // We make a mutable copy of this pointer here because we know Data won't write through it.
            return Data(slicedPointer)
        }
        #else
        // We need to escape into unmanaged land here in order to keep the backing storage alive.
        let unmanagedBacking = Unmanaged.passRetained(base.backing)

        // We can now exfiltrate the storage pointer: this particular layout will be locked forever. Please never do this
        // yourself unless you're really sure!
        self = base.withUnsafeBytes {
            // Slice the base pointer down to just the range we want.
            let slicedPointer = UnsafeRawBufferPointer(rebasing: $0[baseOffset..<endOffset])

            // We make a mutable copy of this pointer here because we know Data won't write through it.
            return Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: slicedPointer.baseAddress!), count: slicedPointer.count, deallocator: .custom { (_: UnsafeMutableRawPointer, _: Int) in unmanagedBacking.release() })
        }
        #endif
    }
}
#endif // Linux or !SwiftPM
