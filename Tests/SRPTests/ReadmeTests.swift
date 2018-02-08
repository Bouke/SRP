import Foundation
import Cryptor
import SRP
import BigInt
import XCTest

class ReadmeTests: XCTestCase {
    func test() throws {
        // This is a database of users, along with their salted verification keys
        let userStore: [String: (salt: Data, verificationKey: Data)] = [
            "alice": createSaltedVerificationKey(username: "alice", password: "password123"),
            "bob": createSaltedVerificationKey(username: "bob", password: "qwerty12345"),
            ]
        
        // Alice wants to authenticate, she sends her username to the server.
        let client = Client(username: "alice", password: "password123")
        try runCommonTest(client: client, userStore: userStore)
    }
    
    func testGivenSrpX() throws {
        // This is a database of users, along with their salted verification keys
        let userStore: [String: (salt: Data, verificationKey: Data)] = [
            "alice": createSaltedVerificationKey(from: BigUInt(12345)),
            "bob": createSaltedVerificationKey(from: BigUInt(67890)),
            ]
        
        // Alice wants to authenticate, she sends her username to the server.
        let client = Client(username: "alice", precomputed_x: BigUInt(12345))
        try runCommonTest(client: client, userStore: userStore)
    }
    
    func runCommonTest(client: Client, userStore: [String: (salt: Data, verificationKey: Data)]) throws {
        // Alice wants to authenticate
        let (username, clientPublicKey) = client.startAuthentication()

        let server = Server(
            username: username,
            salt: userStore[username]!.salt,
            verificationKey: userStore[username]!.verificationKey)

        // The server shares Alice's salt and its public key (the challenge).
        let (salt, serverPublicKey) = server.getChallenge()

        // Alice generates a sessionKey and proofs she generated the correct
        // session key based on her password and the challenge.
        let clientKeyProof = try client.processChallenge(salt: salt, publicKey: serverPublicKey)

        // The server verifies Alices' proof and generates their proof.
        let serverKeyProof = try server.verifySession(publicKey: clientPublicKey, keyProof: clientKeyProof)

        // The client verifies the server's proof.
        try client.verifySession(keyProof: serverKeyProof)

        // At this point, authentication has completed.
        assert(server.isAuthenticated)
        assert(client.isAuthenticated)

        // Both now have the same session key. This key can be used to encrypt
        // further communication between client and server.
        assert(server.sessionKey == client.sessionKey)
    }

    static var allTests : [(String, (ReadmeTests) -> () throws -> Void)] {
        return [
            ("test", test),
            ("testGivenSrpX", testGivenSrpX),
        ]
    }
}
