import Foundation
import Crypto
import SRP
import BigInt
import XCTest

class ReadmeTests: XCTestCase {
    static var allTests: [(String, (ReadmeTests) -> () throws -> Void)] {
        return [
            ("test", test),
            ("testGivenSRPX", testGivenSRPX),
            ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests)
        ]
    }

    func test() throws {
        // This is a database of users, along with their salted verification keys
        let userStore: [String: (salt: Data, verificationKey: Data)] = [
            "alice": createSaltedVerificationKey(using: Insecure.SHA1.self, username: "alice", password: "password123"),
            "bob": createSaltedVerificationKey(using: Insecure.SHA1.self, username: "bob", password: "qwerty12345")
        ]
        // Alice wants to authenticate, she sends her username to the server.
        let client = Client<Insecure.SHA1>(username: "alice", password: "password123")
        try runCommonTest(client: client, userStore: userStore)
    }

    func testGivenSRPX() throws {
        // This is a database of users, along with their salted verification keys
        let userStore: [String: (salt: Data, verificationKey: Data)] = [
            "alice": createSaltedVerificationKey(from: Data("12345".utf8)),
            "bob": createSaltedVerificationKey(from: Data("67890".utf8))
            ]

        // Alice wants to authenticate, she sends her username to the server.
        let client = Client<Insecure.SHA1>(username: "alice", precomputedX: Data("12345".utf8))
        try runCommonTest(client: client, userStore: userStore)
    }

    func runCommonTest<H: HashFunction>(client: Client<H>, userStore: [String: (salt: Data, verificationKey: Data)]) throws {
        // Alice wants to authenticate
        let (username, clientPublicKey) = client.startAuthentication()

        let server = Server<H>(username: username,
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

    // from: https://oleb.net/blog/2017/03/keeping-xctest-in-sync/#appendix-code-generation-with-sourcery
    func testLinuxTestSuiteIncludesAllTests() {
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
        let thisClass = type(of: self)
        let linuxCount = thisClass.allTests.count
        let darwinCount = Int(thisClass
            .defaultTestSuite.testCaseCount)
        XCTAssertEqual(linuxCount,
                       darwinCount,
                       "\(darwinCount - linuxCount) tests are missing from allTests")
        #endif
    }
}
