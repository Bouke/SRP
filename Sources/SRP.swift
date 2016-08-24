import Foundation
import Bignum
import CommonCrypto

public func createSaltedVerificationKey(username: String, password: String, salt: Data? = nil, group: Group = .N2048, alg: Digest = .SHA1) -> (salt: Data, verificationKey: Data) {
    let salt = salt ?? generateRandomBytes(count: 16)
    let x = calculate_x(alg: alg, salt: salt, username: username, password: password)
    let v = calculate_v(group: group, x: x)
    return (salt, v.data)
}

func pad(_ data: Data, to size: Int) -> Data {
    return Data(count: size - data.count) + data
}

//u = H(PAD(A) | PAD(B))
func calculate_u(group: Group, alg: Digest, A: Data, B: Data) -> Bignum {
    let H = alg.hash
    return Bignum(data: H(pad(A, to: group.N.data.count) + pad(B, to: group.N.data.count)))
}

//M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)
func calculate_M(group: Group, alg: Digest, username: String, salt: Data, A: Data, B: Data, K: Data) -> Data {
    let H = alg.hash
    let HN_xor_Hg = (H(group.N.data) ^ H(group.g.data))!
    let HI = H(username.data(using: .utf8)!)
    return H(HN_xor_Hg + HI + salt + A + B + K)
}

//HAMK = H(A | M | K)
func calculate_HAMK(alg: Digest, A: Data, M: Data, K: Data) -> Data {
    let H = alg.hash
    return H(A + M + K)
}

//k = H(N | PAD(g))
func calculate_k(group: Group, alg: Digest) -> Bignum {
    let H = alg.hash
    return Bignum(data: H(group.N.data + pad(group.g.data, to: group.N.data.count)))
}

//x = H(s | H(I | ":" | P))
func calculate_x(alg: Digest, salt: Data, username: String, password: String) -> Bignum {
    let H = alg.hash
    return Bignum(data: H(salt + H("\(username):\(password)".data(using: .utf8)!)))
}

// v = g^x % N
func calculate_v(group: Group, x: Bignum) -> Bignum {
    return mod_exp(group.g, x, group.N)
}
