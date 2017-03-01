import Foundation
import BigInt
import Cryptor

public class Server {
    let b: BigUInt
    public let B: Data

    public let salt: Data
    public let username: String

    let v: BigUInt

    let group: Group
    let algorithm: Digest.Algorithm

    public private(set) var isAuthenticated = false
    public private(set) var sessionKey: Data? = nil

    public init (group: Group = .N2048, algorithm: Digest.Algorithm = .sha1, salt: Data, username: String, verificationKey: Data, secret: Data? = nil) {
        self.group = group
        self.algorithm = algorithm
        self.salt = salt
        self.username = username

        if let secret = secret {
            b = BigUInt(secret)
        } else {
            b = BigUInt(Data(bytes: try! Random.generate(byteCount: 32)))
        }
        let k = calculate_k(group: group, algorithm: algorithm)
        v = BigUInt(verificationKey)
        let N = group.N
        let g = group.g
        // B = (k*v + g^b % N) % N
        B = ((k * v + g.power(b, modulus: N)) % N).serialize()
    }

    public func getChallenge() -> (salt: Data, B: Data) {
        return (salt, B)
    }

    public func verifySession(A: Data, M clientM: Data) throws -> Data {
        let u = calculate_u(group: group, algorithm: algorithm, A: A, B: B)
        let A_ = BigUInt(A)
        let N = group.N

        // shared secret
        // S = (Av^u) mod N
        let S = (A_ * v.power(u, modulus: N)).power(b, modulus: N)

        let H = Digest.hasher(algorithm)
        // K = H(S)
        sessionKey = H(S.serialize())

        let M = calculate_M(group: group, algorithm: algorithm, username: username, salt: salt, A: A, B: B, K: sessionKey!)
        guard clientM == M else { throw SRPError.authenticationFailed }
        isAuthenticated = true

        return calculate_HAMK(algorithm: algorithm, A: A, M: M, K: sessionKey!)
    }
}
