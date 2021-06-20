import Foundation
import BigInt
import Crypto

/// SRP Server; party that verifies the Client's challenge/response
/// against the known password verifier stored for a user.
public class Server<H: HashFunction> {
    let b: BigUInt
    let B: BigUInt

    let salt: Data
    let username: String

    let v: BigUInt
    var K: Data?

    let group: Group
    typealias impl = Implementation<H> // swiftlint:disable:this type_name

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
        privateKey: Data? = nil)
    {
        self.group = group
        self.salt = salt
        self.username = username

        if let privateKey = privateKey {
            b = BigUInt(privateKey)
        } else {
            b = BigUInt(Curve25519.KeyAgreement.PrivateKey().rawRepresentation)
        }
        let k = impl.calculate_k(group: group)
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
        let u = impl.calculate_u(group: group, A: clientPublicKey, B: publicKey)
        let A = BigUInt(clientPublicKey)
        let N = group.N

        guard A % N != 0 else {
            throw AuthenticationFailure.invalidPublicKey
        }

        // shared secret
        // S = (Av^u) mod N
        let S = (A * v.power(u, modulus: N)).power(b, modulus: N)

        // K = H(S)
        let H = impl.H
        K = H(S.serialize())

        let M = impl.calculate_M(group: group, username: username, salt: salt, A: clientPublicKey, B: publicKey, K: K!)
        guard clientKeyProof == M else {
            throw AuthenticationFailure.keyProofMismatch
        }
        isAuthenticated = true

        return impl.calculate_HAMK(A: clientPublicKey, M: M, K: sessionKey!)
    }

    /// The server's public key (A). For every authentication
    /// session a new public key is generated.
    public var publicKey: Data {
        return B.serialize()
    }

    /// The server's private key (a). For every authentication
    /// session a new random private key is generated.
    public var privateKey: Curve25519.KeyAgreement.PrivateKey {
        return try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: b.serialize())
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
