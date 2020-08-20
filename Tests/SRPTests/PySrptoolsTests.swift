import Crypto
import Foundation
import XCTest

@testable import SRP

class PySrptoolsTests: XCTestCase {
    static var allTests: [(String, (PySrptoolsTests) -> () throws -> Void)] {
        return [
            ("testClient", testClient),
            ("testClientUtf8", testClientUtf8),
            ("testServer", testServer),
            ("testServerUtf8", testServerUtf8),
            ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests)
        ]
    }

    func testClient() throws {
        guard ProcessInfo.processInfo.environment["PYTHON"] != nil else {
            return NSLog("Set PYTHON env variable to run test")
        }

        runClientTest(using: Insecure.SHA1.self, group: .N1024, username: "bouke", password: "test")
        runClientTest(using: Insecure.SHA1.self, group: .N2048, username: "bouke", password: "test")
        runClientTest(using: Insecure.SHA1.self, group: .N3072, username: "bouke", password: "test")
        runClientTest(using: Insecure.SHA1.self, group: .N4096, username: "bouke", password: "test")
        runClientTest(using: Insecure.SHA1.self, group: .N6144, username: "bouke", password: "test")
        runClientTest(using: Insecure.SHA1.self, group: .N8192, username: "bouke", password: "test")

        runClientTest(using: SHA256.self, group: .N1024, username: "bouke", password: "test")
        runClientTest(using: SHA256.self, group: .N2048, username: "bouke", password: "test")
        runClientTest(using: SHA256.self, group: .N3072, username: "bouke", password: "test")
        runClientTest(using: SHA256.self, group: .N4096, username: "bouke", password: "test")
        runClientTest(using: SHA256.self, group: .N6144, username: "bouke", password: "test")
        runClientTest(using: SHA256.self, group: .N8192, username: "bouke", password: "test")
    }

    func testClientUtf8() throws {
        guard ProcessInfo.processInfo.environment["PYTHON"] != nil else {
            return NSLog("Set PYTHON env variable to run test")
        }

        runClientTest(using: Insecure.SHA1.self, group: .N1024, username: "bõūkę", password: "tėšt")
    }

    func runClientTest<H: HashFunction>(
        using hashFunction: H.Type,
        group: Group,
        username: String,
        password: String,
        file: StaticString = #file,
        line: UInt = #line)
    {
        let server: RemoteServer<H>
        do {
            server = try RemoteServer(username: username,
                                      password: password,
                                      group: group)
        } catch {
            return XCTFail("Could not start remote server: \(error)", file: file, line: line)
        }
        let client = Client<H>(username: username,
                                password: password,
                                group: group)

        let debugInfo: () -> String = {
            let infos: [String] = [
                "username: \(username)",
                "password: \(password)",
                "group: \(group)",
                "hash function: \(H.self)",
                "salt: \(server.salt?.hex ?? "N/A")",
                "verificationKey: \(server.verificationKey?.hex ?? "N/A")",
                "serverPrivateKey: \(server.privateKey?.hex ?? "N/A")",
                "serverPublicKey: \(server.publicKey?.hex ?? "N/A")",
                "clientPrivateKey: \(client.privateKey.hex)",
                "clientPublicKey: \(client.publicKey.hex)",
                "expected client M: \(server.expectedM?.hex ?? "N/A")",
                "expected server HAMK: \(client.HAMK?.hex ?? "N/A")",
                "clientK: \(client.K?.hex ?? "N/A")"
            ]
            return infos.joined(separator: "\n")
        }

        var additionalDebug: String = ""

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
            additionalDebug += "\nclientM: \(M.hex)"
        } catch {
            return XCTFail("Client couldn't process challenge: \(error) -- \(debugInfo())", file: file, line: line)
        }

        // Using M, the server verifies the proof and calculates a proof for the client
        // Server->Client: H(AMK)
        let HAMK: Data
        do {
            HAMK = try server.verifySession(keyProof: M)
            additionalDebug += "\nserverHAMK: \(HAMK.hex)"
        } catch {
            return XCTFail("Server couldn't verify the session: \(error) -- \(debugInfo())\(additionalDebug)", file: file, line: line)
        }

        // Using H(AMK), the client verifies the server's proof
        do {
            try client.verifySession(keyProof: HAMK)
        } catch {
            return XCTFail("Client couldn't verify the session: \(error) -- \(debugInfo())\(additionalDebug)", file: file, line: line)
        }

        // At this point, the client is authenticated as well
        XCTAssert(client.isAuthenticated)

        // They now share a secret session key
        let serverSessionKey: Data
        do {
            serverSessionKey = try server.getSessionKey()
            additionalDebug += "\nserverK: \(serverSessionKey.hex)"
        } catch {
            return XCTFail("Server didn't provide a session key: \(error) -- \(debugInfo())\(additionalDebug)", file: file, line: line)
        }

        XCTAssertEqual(serverSessionKey, client.sessionKey, "Session keys not equal -- \(debugInfo())\(additionalDebug)", file: file, line: line)
    }

    func testServer() throws {
        guard ProcessInfo.processInfo.environment["PYTHON"] != nil else {
            return NSLog("Set PYTHON env variable to run test")
        }

        runServerTest(using: Insecure.SHA1.self, group: .N1024, username: "bouke", password: "test")
        runServerTest(using: Insecure.SHA1.self, group: .N2048, username: "bouke", password: "test")
        runServerTest(using: Insecure.SHA1.self, group: .N3072, username: "bouke", password: "test")
        runServerTest(using: Insecure.SHA1.self, group: .N4096, username: "bouke", password: "test")
        runServerTest(using: Insecure.SHA1.self, group: .N6144, username: "bouke", password: "test")
        runServerTest(using: Insecure.SHA1.self, group: .N8192, username: "bouke", password: "test")

        runServerTest(using: SHA256.self, group: .N1024, username: "bouke", password: "test")
        runServerTest(using: SHA256.self, group: .N2048, username: "bouke", password: "test")
        runServerTest(using: SHA256.self, group: .N3072, username: "bouke", password: "test")
        runServerTest(using: SHA256.self, group: .N4096, username: "bouke", password: "test")
        runServerTest(using: SHA256.self, group: .N6144, username: "bouke", password: "test")
        runServerTest(using: SHA256.self, group: .N8192, username: "bouke", password: "test")
    }

    func testServerUtf8() throws {
        guard ProcessInfo.processInfo.environment["PYTHON"] != nil else {
            return NSLog("Set PYTHON env variable to run test")
        }

        runServerTest(using: Insecure.SHA1.self, group: .N1024, username: "bõūkę", password: "tėšt")
    }

    func runServerTest<H: HashFunction>(
        using hashFunction: H.Type,
        group: Group,
        username: String,
        password: String,
        file: StaticString = #file,
        line: UInt = #line)
    {
        let (salt, verificationKey) = createSaltedVerificationKey(using: hashFunction,
                                                                  group: group, username: username,
                                                                  password: password)
        let server = Server<H>(username: username,
                                salt: salt,
                                verificationKey: verificationKey,
                                group: group)

        let client: RemoteClient<H>
        do {
            client = try RemoteClient(username: username,
                                      password: password,
                                      group: group)
        } catch {
            return XCTFail("Could not start remote client: \(error)", file: file, line: line)
        }

        let debugInfo: () -> String = {
            let infos: [String] = [
                "username: \(username)",
                "password: \(password)",
                "group: \(group)",
                "hash function: \(H.self)",
                "salt: \(salt.hex)",
                "verificationKey: \(verificationKey.hex)",
                "serverPrivateKey: \(server.privateKey.rawRepresentation.hex)",
                "serverPublicKey: \(server.publicKey.hex)",
                "clientPrivateKey: \(client.privateKey?.hex ?? "N/A")",
                "clientPublicKey: \(client.publicKey?.hex ?? "N/A")"
            ]
            return infos.joined(separator: ", ")
        }

        var additionalDebug: String = ""

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
            additionalDebug += "\nclientM: \(M.hex)"
        } catch {
            return XCTFail("Client couldn't process challenge: \(error) -- \(debugInfo())\(additionalDebug)", file: file, line: line)
        }

        // Using M, the server verifies the proof and calculates a proof for the client
        // Server->Client: H(AMK)
        let HAMK: Data
        do {
            HAMK = try server.verifySession(publicKey: A, keyProof: M)
            additionalDebug += "\nserverHAMK: \(HAMK.hex)"
        } catch {
            return XCTFail("Server couldn't verify the session: \(error) -- \(debugInfo())\(additionalDebug)", file: file, line: line)
        }

        // At this point, the server is authenticated
        XCTAssert(server.isAuthenticated)

        // Using H(AMK), the client verifies the server's proof
        do {
            try client.verifySession(keyProof: HAMK)
        } catch {
            return XCTFail("Client couldn't verify the session: \(error) -- \(debugInfo())\(additionalDebug)", file: file, line: line)
        }

        // They now share a secret session key
        let clientSessionKey: Data
        do {
            clientSessionKey = try client.getSessionKey()
        } catch {
            return XCTFail("Client didn't provide a session key: \(error) -- \(debugInfo())\(additionalDebug)", file: file, line: line)
        }

        XCTAssertEqual(server.sessionKey, clientSessionKey, "Session keys not equal")
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
