import Cryptor
import Foundation
import XCTest

import SRP

class PySrptoolsTests: XCTestCase {
    func testClient() {
        runClientTest(group: .N1024, algorithm: .sha1, username: "bouke", password: "test")
        runClientTest(group: .N2048, algorithm: .sha1, username: "bouke", password: "test")
        runClientTest(group: .N3072, algorithm: .sha1, username: "bouke", password: "test")
        runClientTest(group: .N4096, algorithm: .sha1, username: "bouke", password: "test")
        runClientTest(group: .N6144, algorithm: .sha1, username: "bouke", password: "test")
        runClientTest(group: .N8192, algorithm: .sha1, username: "bouke", password: "test")

        runClientTest(group: .N1024, algorithm: .sha256, username: "bouke", password: "test")
        runClientTest(group: .N2048, algorithm: .sha256, username: "bouke", password: "test")
        runClientTest(group: .N3072, algorithm: .sha256, username: "bouke", password: "test")
        runClientTest(group: .N4096, algorithm: .sha256, username: "bouke", password: "test")
        runClientTest(group: .N6144, algorithm: .sha256, username: "bouke", password: "test")
        runClientTest(group: .N8192, algorithm: .sha256, username: "bouke", password: "test")
    }

    func runClientTest(
        group: Group,
        algorithm: Digest.Algorithm,
        username: String,
        password: String,
        file: StaticString = #file,
        line: UInt = #line)
    {
        let server: RemoteServer
        do {
            server = try RemoteServer(username: username, password: password, group: group, algorithm: algorithm)
        } catch {
            return XCTFail("Could not start remote server: \(error)", file: file, line: line)
        }
        let client = Client(username: username, password: password, group: group, algorithm: algorithm)

        let debugInfo: () -> String = {
            return [
                "username: \(username)",
                "password: \(password)",
                "group: \(group)",
                "algorithm: \(algorithm)",
                "salt: \(server.salt?.hex ?? "N/A")",
                "verificationKey: \(server.verificationKey?.hex ?? "N/A")",
                "serverPrivateKey: \(server.privateKey?.hex ?? "N/A")",
                "clientPrivateKey: \(client.privateKey.hex)"
            ].joined(separator: ", ")
        }

        // The server generates the challenge: pre-defined salt, public key B
        // Server->Client: salt, B
        let s: Data
        let B: Data
        do {
            (s, B) = try server.getChallenge(publicKey: client.publicKey)
        } catch {
            return XCTFail("Server didn't return a challenge: \(error) -- \(debugInfo())", file: file, line: line)
        }

        // Using (salt, B), the client generates the proof M
        // Client->Server: M
        let M: Data
        do {
            M = try client.processChallenge(salt: s, publicKey: B)
        } catch {
            return XCTFail("Client couldn't process challenge: \(error) -- \(debugInfo())")
        }

        // Using M, the server verifies the proof and calculates a proof for the client
        // Server->Client: H(AMK)
        let HAMK: Data
        do {
            HAMK = try server.verifySession(keyProof: M)
        } catch {
            return XCTFail("Server couldn't verify the session: \(error) -- \(debugInfo())", file: file, line: line)
        }

        // Using H(AMK), the client verifies the server's proof
        do {
            try client.verifySession(keyProof: HAMK)
        } catch {
            return XCTFail("Client couldn't verify the session: \(error) -- \(debugInfo())", file: file, line: line)
        }

        // At this point, the client is authenticated as well
        XCTAssert(client.isAuthenticated)

        // They now share a secret session key
        let serverSessionKey: Data
        do {
            serverSessionKey = try server.getSessionKey()
        } catch {
            return XCTFail("Server didn't provide a session key: \(error) -- \(debugInfo())", file: file, line: line)
        }

        XCTAssertEqual(serverSessionKey, client.sessionKey, "Session keys not equal -- \(debugInfo())")
    }

    func testServer() {
        runServerTest(group: .N1024, algorithm: .sha1, username: "bouke", password: "test")
        runServerTest(group: .N2048, algorithm: .sha1, username: "bouke", password: "test")
        runServerTest(group: .N3072, algorithm: .sha1, username: "bouke", password: "test")
        runServerTest(group: .N4096, algorithm: .sha1, username: "bouke", password: "test")
        runServerTest(group: .N6144, algorithm: .sha1, username: "bouke", password: "test")
        runServerTest(group: .N8192, algorithm: .sha1, username: "bouke", password: "test")

        runServerTest(group: .N1024, algorithm: .sha256, username: "bouke", password: "test")
        runServerTest(group: .N2048, algorithm: .sha256, username: "bouke", password: "test")
        runServerTest(group: .N3072, algorithm: .sha256, username: "bouke", password: "test")
        runServerTest(group: .N4096, algorithm: .sha256, username: "bouke", password: "test")
        runServerTest(group: .N6144, algorithm: .sha256, username: "bouke", password: "test")
        runServerTest(group: .N8192, algorithm: .sha256, username: "bouke", password: "test")
    }

    func runServerTest(
        group: Group,
        algorithm: Digest.Algorithm,
        username: String,
        password: String,
        file: StaticString = #file,
        line: UInt = #line)
    {
        let (salt, verificationKey) = createSaltedVerificationKey(username: username, password: password, group: group, algorithm: algorithm)
        let server = Server(username: username, salt: salt, verificationKey: verificationKey, group: group, algorithm: algorithm)

        let client: RemoteClient
        do {
            client = try RemoteClient(username: username, password: password, group: group, algorithm: algorithm)
        } catch {
            return XCTFail("Could not start remote client: \(error)", file: file, line: line)
        }

        let debugInfo: () -> String = {
            return [
                "username: \(username)",
                "password: \(password)",
                "group: \(group)",
                "algorithm: \(algorithm)",
                "salt: \(salt.hex)",
                "verificationKey: \(verificationKey.hex)",
                "serverPrivateKey: \(server.privateKey.hex)",
                "clientPrivateKey: \(client.privateKey?.hex ?? "N/A")"
            ].joined(separator: ", ")
        }

        let A: Data
        do {
            (_, A) = try client.startAuthentication()
        } catch {
            return XCTFail("Client didn't return public key: \(error) -- \(debugInfo())", file: file, line: line)
        }

        // The server generates the challenge: pre-defined salt, public key B
        // Server->Client: salt, B
        let (s, B) = server.getChallenge()

        // Using (salt, B), the client generates the proof M
        // Client->Server: M
        let M: Data
        do {
            M = try client.processChallenge(salt: s, publicKey: B)
        } catch {
            return XCTFail("Client couldn't process challenge: \(error) -- \(debugInfo())", file: file, line: line)
        }

        // Using M, the server verifies the proof and calculates a proof for the client
        // Server->Client: H(AMK)
        let HAMK: Data
        do {
            HAMK = try server.verifySession(publicKey: A, keyProof: M)
        } catch {
            return XCTFail("Server couldn't verify the session: \(error) -- \(debugInfo())", file: file, line: line)
        }

        // At this point, the server is authenticated
        XCTAssert(server.isAuthenticated)

        // Using H(AMK), the client verifies the server's proof
        do {
            try client.verifySession(keyProof: HAMK)
        } catch {
            return XCTFail("Client couldn't verify the session: \(error) -- \(debugInfo())", file: file, line: line)
        }

        // They now share a secret session key
        let clientSessionKey: Data
        do {
            clientSessionKey = try client.getSessionKey()
        } catch {
            return XCTFail("Client didn't provide a session key: \(error) -- \(debugInfo())", file: file, line: line)
        }

        XCTAssertEqual(server.sessionKey, clientSessionKey, "Session keys not equal")
    }

    static var allTests : [(String, (PySrptoolsTests) -> () throws -> Void)] {
        return [
            ("testClient", testClient),
            ("testServer", testServer),
        ]
    }
}
