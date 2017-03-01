import Foundation

enum DataDecodingError: Error {
    case oddStringLength(Int)
}

extension Data {
    init(hex: String) throws {
        if hex.utf8.count % 2 == 1 {
            throw DataDecodingError.oddStringLength(hex.utf8.count)
        }
        let bytes = stride(from: 0, to: hex.utf8.count, by: 2)
            .map { hex.utf8.index(hex.utf8.startIndex, offsetBy: $0) }
            .map { hex.utf8[$0...hex.utf8.index(after: $0)] }
            .map { UInt8(String($0)!, radix: 16)! }
        self.init(bytes: bytes)
    }
    var hex: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
