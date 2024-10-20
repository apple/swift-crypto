import Foundation

extension Optional where Wrapped == ContiguousBytes {
    func withUnsafeBytes<ReturnValue>(_ body: (UnsafeRawBufferPointer) throws -> ReturnValue) rethrows -> ReturnValue {
        if let self {
            return try self.withUnsafeBytes { try body($0) }
        } else {
            return try body(UnsafeRawBufferPointer(start: nil, count: 0))
        }
    }
}