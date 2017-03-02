import Foundation
import BigInt
import Cryptor

public class Client {
    let a: BigUInt
    let A: BigUInt

    let group: Group
    let algorithm: Digest.Algorithm

    let username: String
    let password: String

    var HAMK: Data? = nil
    var K: Data? = nil

    /// Whether the session is authenticated, i.e. the password
    /// was verified by the server and proof of a valid session
    /// key was provided by the server. If `true`, `sessionKey`
    /// is also available.
    public private(set) var isAuthenticated = false

    public init(
        group: Group = .N2048,
        algorithm: Digest.Algorithm = .sha1,
        username: String,
        password: String,
        secret: Data? = nil)
    {
        self.group = group
        self.algorithm = algorithm
        self.username = username
        self.password = password

        if let secret = secret {
            a = BigUInt(secret)
        } else {
            a = BigUInt(Data(bytes: try! Random.generate(byteCount: 32)))
        }
        // A = g^a % N
        A = group.g.power(a, modulus: group.N)
    }

    public func startAuthentication() -> (username: String, publicKey: Data) {
        return (username, publicKey)
    }

    public func processChallenge(salt: Data, B: Data) -> Data {
        let H = Digest.hasher(algorithm)
        let N = group.N

        let u = calculate_u(group: group, algorithm: algorithm, A: publicKey, B: B)
        let k = calculate_k(group: group, algorithm: algorithm)
        let x = calculate_x(algorithm: algorithm, salt: salt, username: username, password: password)
        let v = calculate_v(group: group, x: x)

        let B_ = BigUInt(B)

        // shared secret
        // S = (B - kg^x) ^ (a + ux)
        // Note that v = g^x, and that B - kg^x might become negative, which 
        // cannot be stored in BigUInt. So we'll add N to B_ and make sure kv
        // isn't greater than N.
        let S = (B_ + N - k * v % N).power(a + u * x, modulus: N)

        // session key
        K = H(S.serialize())

        // client verification
        let M = calculate_M(group: group, algorithm: algorithm, username: username, salt: salt, A: publicKey, B: B, K: K!)

        // server verification
        HAMK = calculate_HAMK(algorithm: algorithm, A: publicKey, M: M, K: K!)
        return M
    }

    /// After the server has verified that the password is correct,
    /// it will send proof of the derived session key. This is verified
    /// on our end and finalizes the authentication session. After this
    /// step, the `sessionKey` is available.
    ///
    /// - Parameter HAMK: proof of the server that it derived the same
    ///     session key.
    /// - Throws: `SRPError.authenticationFailed` if the proof couldn't
    ///     be verified.
    public func verifySession(HAMK serverHAMK: Data) throws {
        guard let HAMK = HAMK else { throw SRPError.authenticationFailed }
        guard HAMK == serverHAMK else { throw SRPError.authenticationFailed }
        isAuthenticated = true
    }

    /// The client's public key (A). For every authentication
    /// session a new public key is generated.
    public var publicKey: Data {
        return A.serialize()
    }

    /// The client's private key (a). For every authentication
    /// session a new random private key is generated.
    public var privateKey: Data {
        return a.serialize()
    }

    /// The session key that is exchanged during authentication.
    /// This key can be used to encrypt further communication
    /// between client and server.
    public var sessionKey: Data? {
        guard isAuthenticated else {
            return nil
        }
        return K
    }
}
