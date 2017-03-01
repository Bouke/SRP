import XCTest
import CommonCrypto

@testable import SRP

class PySrptoolsTests: XCTestCase {
    func testSrptoolsServer() {
        runServerTest(group: .N1024, algorithm: .SHA1, username: "bouke", password: "test")
        runServerTest(group: .N2048, algorithm: .SHA1, username: "bouke", password: "test")
        runServerTest(group: .N3072, algorithm: .SHA1, username: "bouke", password: "test")
        runServerTest(group: .N4096, algorithm: .SHA1, username: "bouke", password: "test")
        runServerTest(group: .N6144, algorithm: .SHA1, username: "bouke", password: "test")
        runServerTest(group: .N8192, algorithm: .SHA1, username: "bouke", password: "test")
    }

    func runServerTest(
        group: Group,
        algorithm: Digest,
        username: String,
        password: String,
        file: StaticString = #file,
        line: UInt = #line)
    {
        let server: RemoteServer
        do {
            server = try RemoteServer(group: group, alg: algorithm, username: username, password: password)
        } catch {
            return XCTFail("Could not start remote server: \(error)", file: file, line: line)
        }
        let client = Client(group: group, alg: algorithm, username: username, password: password)

        // The server generates the challenge: pre-defined salt, public key B
        // Server->Client: salt, B
        let s: Data
        let B: Data
        do {
            (s, B) = try server.getChallenge(A: client.A)
        } catch {
            return XCTFail("Server didn't return a challenge: \(error)", file: file, line: line)
        }

        // Using (salt, B), the client generates the proof M
        // Client->Server: M
        let M = client.processChallenge(salt: s, B: B)

        // Using M, the server verifies the proof and calculates a proof for the client
        // Server->Client: H(AMK)
        let HAMK: Data
        do {
            HAMK = try server.verifySession(M: M)
        } catch {
            return XCTFail("Server couldn't verify the session: \(error)", file: file, line: line)
        }

        // Using H(AMK), the client verifies the server's proof
        do {
            try client.verifySession(HAMK: HAMK)
        } catch {
            return XCTFail("Client couldn't verify the session: \(error)", file: file, line: line)
        }

        // At this point, the client is authenticated as well
        XCTAssert(client.isAuthenticated)

        // They now share a secret session key
        let serverSessionKey: Data
        do {
            serverSessionKey = try server.get_session_key()
        } catch {
            return XCTFail("Server didn't provide a session key: \(error)", file: file, line: line)
        }

        XCTAssertEqual(serverSessionKey, client.sessionKey, "Session keys not equal")
    }

    static var allTests : [(String, (PySrptoolsTests) -> () throws -> Void)] {
        return [
            ("testSrptoolsServer", testSrptoolsServer),
        ]
    }
}
