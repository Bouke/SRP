import Foundation
import BigInt
import Cryptor

public func createSaltedVerificationKey(
    username: String,
    password: String,
    salt: Data? = nil,
    group: Group = .N2048,
    algorithm: Digest.Algorithm = .sha1)
    -> (salt: Data, verificationKey: Data)
{
    let salt = salt ?? Data(bytes: try! Random.generate(byteCount: 16))
    let x = calculate_x(algorithm: algorithm, salt: salt, username: username, password: password)
    let v = calculate_v(group: group, x: x)
    return (salt, v.serialize())
}

func pad(_ data: Data, to size: Int) -> Data {
    precondition(size >= data.count, "Negative padding not possible")
    return Data(count: size - data.count) + data
}

//u = H(PAD(A) | PAD(B))
func calculate_u(group: Group, algorithm: Digest.Algorithm, A: Data, B: Data) -> BigUInt {
    let H = Digest.hasher(algorithm)
    let size = group.N.serialize().count
    return BigUInt(H(pad(A, to: size) + pad(B, to: size)))
}

//M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)
func calculate_M(group: Group, algorithm: Digest.Algorithm, username: String, salt: Data, A: Data, B: Data, K: Data) -> Data {
    let H = Digest.hasher(algorithm)
    let HN_xor_Hg = (H(group.N.serialize()) ^ H(group.g.serialize()))!
    let HI = H(username.data(using: .utf8)!)
    return H(HN_xor_Hg + HI + salt + A + B + K)
}

//HAMK = H(A | M | K)
func calculate_HAMK(algorithm: Digest.Algorithm, A: Data, M: Data, K: Data) -> Data {
    let H = Digest.hasher(algorithm)
    return H(A + M + K)
}

//k = H(N | PAD(g))
func calculate_k(group: Group, algorithm: Digest.Algorithm) -> BigUInt {
    let H = Digest.hasher(algorithm)
    let size = group.N.serialize().count
    return BigUInt(H(group.N.serialize() + pad(group.g.serialize(), to: size)))
}

//x = H(s | H(I | ":" | P))
func calculate_x(algorithm: Digest.Algorithm, salt: Data, username: String, password: String) -> BigUInt {
    let H = Digest.hasher(algorithm)
    return BigUInt(H(salt + H("\(username):\(password)".data(using: .utf8)!)))
}

// v = g^x % N
func calculate_v(group: Group, x: BigUInt) -> BigUInt {
    return group.g.power(x, modulus: group.N)
}
