import Foundation
import BigInt
import Cryptor

public class Server {
    let b: BigUInt
    let B: BigUInt

    public let salt: Data
    public let username: String

    let v: BigUInt
    var K: Data? = nil

    let group: Group
    let algorithm: Digest.Algorithm

    public private(set) var isAuthenticated = false

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
        B = ((k * v + g.power(b, modulus: N)) % N)
    }

    public func getChallenge() -> (salt: Data, publicKey: Data) {
        return (salt, publicKey)
    }

    public func verifySession(A: Data, M clientM: Data) throws -> Data {
        let u = calculate_u(group: group, algorithm: algorithm, A: A, B: publicKey)
        let A_ = BigUInt(A)
        let N = group.N

        // shared secret
        // S = (Av^u) mod N
        let S = (A_ * v.power(u, modulus: N)).power(b, modulus: N)

        let H = Digest.hasher(algorithm)
        // K = H(S)
        K = H(S.serialize())

        let M = calculate_M(group: group, algorithm: algorithm, username: username, salt: salt, A: A, B: publicKey, K: sessionKey!)
        guard clientM == M else { throw SRPError.authenticationFailed }
        isAuthenticated = true

        return calculate_HAMK(algorithm: algorithm, A: A, M: M, K: sessionKey!)
    }

    /// The server's public key (A). For every authentication
    /// session a new public key is generated.
    public var publicKey: Data {
        return B.serialize()
    }

    /// The server's private key (a). For every authentication
    /// session a new random private key is generated.
    public var privateKey: Data {
        return b.serialize()
    }

    /// The session key (K) that is exchanged during authentication.
    /// This key can be used to encrypt further communication
    /// between client and server.
    public var sessionKey: Data? {
        guard isAuthenticated else {
            return nil
        }
        return K
    }
}
