import Foundation
import BigInt
import Cryptor

/// SRP Server; party that verifies the Client's challenge/response 
/// against the known password verifier stored for a user.
public class Server {
    let b: BigUInt
    let B: BigUInt

    let salt: Data
    let username: String

    let v: BigUInt
    var K: Data?

    let group: Group
    let algorithm: Digest.Algorithm

    /// Whether the session is authenticated, i.e. the password
    /// was verified by the server and proof of a valid session
    /// key was provided by the server. If `true`, `sessionKey`
    /// is also available.
    public private(set) var isAuthenticated = false

    /// Initialize the Server SRP party. The username is provided
    /// by the Client. The salt and verificationKey have been 
    /// stored prior to the authentication attempt.
    ///
    /// - Parameters:
    ///   - username: username (I) provided by the client.
    ///   - salt: salt (s) stored for this username.
    ///   - verificationKey: verification key (v) stored for this
    ///       username.
    ///   - group: which `Group` to use, must be the same for the
    ///       client as well as the pre-stored verificationKey.
    ///   - algorithm: which `Digest.Algorithm` to use, again this
    ///       must be the same for the client as well as the pre-stored
    ///       verificationKey.
    ///   - privateKey: (optional) custom private key (b); if providing
    ///       the private key of the `Server`, make sure to provide a
    ///       good random key of at least 32 bytes. Default is to
    ///       generate a private key of 128 bytes. You MUST not re-use
    ///       the private key between sessions. However the private key
    ///       might be shared when running multiple instances and an
    ///       authentication session might be handled by multiple
    ///       instances.
    public init(
        username: String,
        salt: Data,
        verificationKey: Data,
        group: Group = .N2048,
        algorithm: Digest.Algorithm = .sha1,
        privateKey: Data? = nil)
    {
        self.group = group
        self.algorithm = algorithm
        self.salt = salt
        self.username = username

        if let privateKey = privateKey {
            b = BigUInt(privateKey)
        } else {
            b = BigUInt(Data(bytes: try! Random.generate(byteCount: 128)))
        }
        let k = calculate_k(group: group, algorithm: algorithm)
        v = BigUInt(verificationKey)
        let N = group.N
        let g = group.g
        // B = (k*v + g^b) % N
        // BigInt library doesnt have x^y but x^y%z instead, so we calculate B:
        // B = (k*v + g^b % N) % N
        B = ((k * v + g.power(b, modulus: N)) % N)
    }

    /// Returns the challenge. This method is a no-op.
    ///
    /// - Returns: `salt` (s) and `publicKey` (B)
    public func getChallenge() -> (salt: Data, publicKey: Data) {
        return (salt, publicKey)
    }

    /// Verify that the client did generate the correct `sessionKey`
    /// from their password and the challenge we provided. We'll generate
    /// the `sessionKey` as well and proof the client we have posession
    /// of the password verifier and thus generated the same `sessionKey`
    /// from that.
    ///
    /// - Parameters:
    ///   - clientPublicKey: client's public key
    ///   - clientKeyProof: client's proof of `sessionKey`
    /// - Returns: our proof of `sessionKey` (H(A|M|K))
    /// - Throws:
    ///    - `AuthenticationFailure.invalidPublicKey` if the client's public
    ///      key is invalid (i.e. B % N is zero).
    ///    - `AuthenticationFailure.keyProofMismatch` if the proof
    ///      doesn't match our own.
    public func verifySession(publicKey clientPublicKey: Data, keyProof clientKeyProof: Data) throws -> Data {
        let u = calculate_u(group: group, algorithm: algorithm, A: clientPublicKey, B: publicKey)
        let A = BigUInt(clientPublicKey)
        let N = group.N

        guard A % N != 0 else {
            throw AuthenticationFailure.invalidPublicKey
        }

        // shared secret
        // S = (Av^u) mod N
        let S = (A * v.power(u, modulus: N)).power(b, modulus: N)

        let H = Digest.hasher(algorithm)
        // K = H(S)
        K = H(S.serialize())

        let M = calculate_M(group: group, algorithm: algorithm, username: username, salt: salt, A: clientPublicKey, B: publicKey, K: K!)
        guard clientKeyProof == M else {
            throw AuthenticationFailure.keyProofMismatch
        }
        isAuthenticated = true

        return calculate_HAMK(algorithm: algorithm, A: clientPublicKey, M: M, K: sessionKey!)
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
