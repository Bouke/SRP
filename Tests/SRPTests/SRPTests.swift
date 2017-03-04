import Foundation
import Cryptor
import SRP
import XCTest

class SRPTests: XCTestCase {
    func testSuccess() {
        let username = "Pair-Setup"
        let password = "001-02-003"

        /* Create a salt+verification key for the user's password. The salt and
         * key need to be computed at the time the user's password is set and
         * must be stored by the server-side application for use during the
         * authentication process.
         */
        let (salt, verificationKey) = createSaltedVerificationKey(username: username, password: password)

        // Begin authentication process
        let client = Client(username: username, password: password)
        let (_, A) = client.startAuthentication()

        // Client->Server: I (username)
        // Server retrieves salt and verificationKey from permanent storage
        let server = Server(username: username, salt: salt, verificationKey: verificationKey, secret: Data(bytes: try! Random.generate(byteCount: 32)))

        // The server generates the challenge: pre-defined salt, public key B
        // Server->Client: salt, B
        let (_, B) = server.getChallenge()

        // Using (salt, B), the client generates the proof M
        // Client->Server: M
        let M: Data
        do {
            M = try client.processChallenge(salt: salt, publicKey: B)
        } catch {
            return XCTFail("Client couldn't process challenge: \(error)")
        }

        XCTAssertFalse(server.isAuthenticated)
        XCTAssertFalse(client.isAuthenticated)

        let HAMK: Data
        do {
            // Using M, the server verifies the proof and calculates a proof for the client
            // Server->Client: H(AMK)
            HAMK = try server.verifySession(publicKey: A, keyProof: M)
        } catch {
            return XCTFail("Client generated invalid M")
        }

        // At this point, the server is authenticated.
        XCTAssert(server.isAuthenticated)
        XCTAssertFalse(client.isAuthenticated)

        do {
            // Using H(AMK), the client verifies the server's proof
            try client.verifySession(keyProof: HAMK)
        } catch {
            return XCTFail("Server generated invalid H(AMK)")
        }

        // At this point, the client is authenticated as well
        XCTAssert(server.isAuthenticated)
        XCTAssert(client.isAuthenticated)

        // They now share a secret session key
        guard let K0 = server.sessionKey, let K1 = client.sessionKey else {
            return XCTFail("Session keys not set")
        }
        XCTAssertEqual(K0, K1, "Session keys not equal")
    }

    func testClientAborts() {
        let client = Client(username: "alice", password: "password123")
        do {
            _ = try client.processChallenge(
                salt: try! Data(hex: String(repeating: "0", count: 16)),
                publicKey: try! Data(hex: String(repeating: "0", count: 512)))
            XCTFail("Should not have processed the challenge")
        } catch AuthenticationFailure.invalidPublicKey {
            // success
        } catch {
            XCTFail("Incorrect error thrown: \(error)")
        }
    }

    func testServerAborts() {
        let (salt, verificationKey) = createSaltedVerificationKey(username: "alice", password: "password123")
        let server = Server(username: "alice", salt: salt, verificationKey: verificationKey)
        do {
            _ = try server.verifySession(
                publicKey: try! Data(hex: String(repeating: "0", count: 512)),
                keyProof: try! Data(hex: String(repeating: "0", count: 512)))
            XCTFail("Should not have verified the session")
        } catch AuthenticationFailure.invalidPublicKey {
            // success
        } catch {
            XCTFail("Incorrect error thrown: \(error)")
        }
    }

    static var allTests : [(String, (SRPTests) -> () throws -> Void)] {
        return [
            ("testSuccess", testSuccess),
            ("testClientAborts", testClientAborts),
            ("testServerAborts", testServerAborts),
        ]
    }
}
