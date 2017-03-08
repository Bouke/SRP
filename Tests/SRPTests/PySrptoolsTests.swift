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

    func testClientUtf8() {
        runClientTest(group: .N1024, algorithm: .sha1, username: "bõūkę", password: "tėšt")
    }


    func runClientTest(
        group: Group,
        algorithm: Digest.Algorithm,
        username: String,
        password: String,
        file: StaticString = #file,
        line: UInt = #line)
    {
        // Because of an interoperability issue with the library `srptools`,
        // the keys and salt are predefined. When the issue has been resolved,
        // these should be randomly generated again.
        //-TODO: make tests random again after https://github.com/idlesign/srptools/issues/2 has been resolved

        let server: RemoteServer
        do {
            server = try RemoteServer(username: username,
                                      password: password,
                                      group: group,
                                      algorithm: algorithm,
                                      secret: try! Data(hex: "a6edb28a37955142e77bd767bf2f41e823904a9b37e5ef9538f7d804553a9f9b17b254e199c85747522dba571293d16d0a6a1e792d29fda0196e3c2ee4c72d37ae20d9521dfcc1395da6ceb2cb2dd5f86c40c66c61f68d1f6c000c0b6dc6043be720d12bd3fbb9ce2f775ef90fc4f9c0567cfcaabc4fc0d7459f5790114a2dfb"),
                                      salt: try! Data(hex: "5c90beb7c6976084"))
        } catch {
            return XCTFail("Could not start remote server: \(error)", file: file, line: line)
        }
        let client = Client(username: username,
                            password: password,
                            group: group,
                            algorithm: algorithm,
                            secret: try! Data(hex: "e8bf050e0184b5cd5207a56a432386a41b22017ad77a9259914271e226036ed9"))

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

    func testServerUtf8() {
        runServerTest(group: .N1024, algorithm: .sha1, username: "bõūkę", password: "tėšt")
    }

    func runServerTest(
        group: Group,
        algorithm: Digest.Algorithm,
        username: String,
        password: String,
        file: StaticString = #file,
        line: UInt = #line)
    {
        // Because of an interoperability issue with the library `srptools`,
        // the keys and salt are predefined. When the issue has been resolved,
        // these should be randomly generated again.
        //-TODO: make tests random again after https://github.com/idlesign/srptools/issues/2 has been resolved

        let (salt, verificationKey) = createSaltedVerificationKey(username: username,
                                                                  password: password,
                                                                  salt: try! Data(hex: "3c1f72d18855ea5bf47ffd404868e715"),
                                                                  group: group,
                                                                  algorithm: algorithm)
        let server = Server(username: username,
                            salt: salt,
                            verificationKey: verificationKey,
                            group: group,
                            algorithm: algorithm,
                            secret: try! Data(hex: "cc6c536ecc84b45fe248fba7efec7f654707004f84be125b55fad246d16c94dc"))

        let client: RemoteClient
        do {
            client = try RemoteClient(username: username,
                                      password: password,
                                      group: group,
                                      algorithm: algorithm,
                                      secret: try! Data(hex: "9b06aedbc7c74734ac4053d31114b60aaffbf228c24c316ea6e141fb0c5f4c76639e63b6351e342fe10c7a641086b878cb10a1415f2afcba30229bc795f08bed3f09a2fe990c26c9a5f9c08f4a064cc6f1e83cb4863895eb37bd4e4325c95d1417e2ebd1a152b275c68bea8c7c4b952d658729ff0e99bc928173040c2b686b99"))
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
            ("testClientUtf8", testClientUtf8),
            ("testServer", testServer),
            ("testServerUtf8", testServerUtf8),
        ]
    }
}
