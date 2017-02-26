import Foundation
import BigInt
import CommonCrypto

public class Client {
    let a: BigUInt
    public let A: Data

    let group: Group
    let alg: Digest

    let username: String
    let password: String

    var HAMK: Data? = nil

    public private(set) var isAuthenticated = false
    public private(set) var sessionKey: Data? = nil

    public init (group: Group = .N2048, alg: Digest = .SHA1, username: String, password: String, secret: Data? = nil) {
        self.group = group
        self.alg = alg
        self.username = username
        self.password = password

        if let secret = secret {
            a = BigUInt(secret)
        } else {
            a = BigUInt(generateRandomBytes(count: 32))
        }
        // A = g^a % N
        A = group.g.power(a, modulus: group.N).serialize()
    }

    public func startAuthentication() -> (username: String, A: Data) {
        return (username, A)
    }

    public func processChallenge(salt: Data, B: Data) -> Data {
        let H = alg.hash
        let N = group.N

        let u = calculate_u(group: group, alg: alg, A: A, B: B)
        let k = calculate_k(group: group, alg: alg)
        let x = calculate_x(alg: alg, salt: salt, username: username, password: password)
        let v = calculate_v(group: group, x: x)

        let B_ = BigUInt(B)

        // shared secret
        // S = (B - kg^x) ^ (a + ux)
        // Note that v = g^x, and that B - kg^x might become negative, which 
        // cannot be stored in BigUInt. So we'll add N to B_ and make sure kv
        // isn't greater than N.
        let S = (B_ + N - k * v % N).power(a + u * x, modulus: N)

        // session key
        sessionKey = H(S.serialize())

        // client verification
        let M = calculate_M(group: group, alg: alg, username: username, salt: salt, A: A, B: B, K: sessionKey!)

        // server verification
        HAMK = calculate_HAMK(alg: alg, A: A, M: M, K: sessionKey!)
        return M
    }

    public func verifySession(HAMK serverHAMK: Data) throws {
        guard let HAMK = HAMK else { throw Error.authenticationFailed }
        guard HAMK == serverHAMK else { throw Error.authenticationFailed }
        isAuthenticated = true
    }
}
