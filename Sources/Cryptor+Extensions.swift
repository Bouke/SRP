import Cryptor
import Foundation

extension Digest {
    static func hasher(_ algorithm: Algorithm) -> (Data) -> Data {
        return { data in
            let digest = Digest(using: algorithm)
            _ = digest.update(data: data)
            return Data(bytes: digest.final())
        }
    }
}
