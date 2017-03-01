import XCTest
import CommonCrypto

@testable import SRP

enum RemoteError: Error {
    case noPython
    case unexpectedPrompt(String)
    case commandFailure
    case commandFailureWithMessage(String)
    case valueExpected
    case unexpectedValueLabel(String)
    case decodingError
    case unexpectedExit
}

class RemoteServer {
    private let process = Process()

    private let standardOutput = Pipe()
    private var standardOutputBuffer = Data()

    private let standardInput = Pipe()
    private let standardError = Pipe()

    init(group: Group = .N2048, alg: Digest = .SHA1, username: String, password: String) throws {
        guard let python = ProcessInfo.processInfo.environment["PYTHON"] else {
            throw RemoteError.noPython
        }

        let remotepy = URL(fileURLWithPath: #file)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("remote.py")

        process.launchPath = python
        process.arguments = [remotepy.path,
                             username,
                             password,
                             "--group", "\(group)",
                             "--algorithm", "\(alg)"]
        process.standardInput = standardInput
        process.standardOutput = standardOutput
        process.standardError = standardError

        process.launch()
    }

    /// Get server's challenge
    ///
    /// - Parameter A:
    /// - Returns: (salt, B)
    /// - Throws: on I/O Error
    func getChallenge(A: Data) throws -> (s: Data, B: Data) {
        do {
            try write(prompt: "A", line: A.hex)
            let s = try Data(hex: try read(label: "s"))
            let B = try Data(hex: try read(label: "B"))
            return (s, B)
        } catch RemoteError.unexpectedExit {
            throw error()
        }
    }

    /// Verify the user's response
    ///
    /// - Parameter M:
    /// - Returns: HAMK
    /// - Throws: on I/O Error
    func verifySession(M: Data) throws -> Data {
        do {
            try write(prompt: "M", line: M.hex)
            return try Data(hex: try read(label: "HAMK"))
        } catch RemoteError.unexpectedExit {
            throw error()
        }
    }

    /// Returns the server's session key
    ///
    /// - Returns: session key
    /// - Throws: on I/O Error
    func get_session_key() throws -> Data {
        return try Data(hex: try read(label: "K"))
    }

    private func write(prompt expectedPrompt: String, line: String) throws {
        let prompt = try readprompt()
        guard prompt == "\(expectedPrompt): " else {
            throw RemoteError.unexpectedPrompt(prompt)
        }
        writeline(line)
    }

    private func writeline(_ line: String) {
        standardInput.fileHandleForWriting.write("\(line)\n".data(using: .ascii)!)
    }

    private func readprompt() throws -> String {
        if !process.isRunning {
            throw RemoteError.unexpectedExit
        }
        if standardOutputBuffer.count > 0 {
            defer { standardOutputBuffer = Data() }
            return String(data: standardOutputBuffer, encoding: .ascii)!
        } else {
            return String(data: standardOutput.fileHandleForReading.availableData, encoding: .ascii)!
        }
    }

    private func read(label: String) throws -> (String) {
        let splitted = try readline().components(separatedBy: ": ")
        guard splitted.count == 2 else {
            throw RemoteError.valueExpected
        }
        guard label == splitted[0] else {
            throw RemoteError.unexpectedValueLabel(splitted[0])
        }
        return splitted[1]
    }

    private func readline() throws -> String {
        repeat {
            if let eol = standardOutputBuffer.index(of: 10) {
                defer {
                    standardOutputBuffer.removeFirst(eol + 1)
                }
                guard let line = String(data: Data(standardOutputBuffer[0..<eol]), encoding: .ascii) else {
                    throw RemoteError.decodingError
                }
                return line
            }
            standardOutputBuffer.append(standardOutput.fileHandleForReading.availableData)
        } while process.isRunning
        throw RemoteError.unexpectedExit
    }

    private func error() -> RemoteError {
        let error = standardError.fileHandleForReading.readDataToEndOfFile()
        guard let message = String(data: error, encoding: .utf8) else {
            return RemoteError.commandFailure
        }
        return RemoteError.commandFailureWithMessage(message)
    }
}

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
