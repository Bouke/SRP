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
    func get_challenge(A: Data) throws -> (s: Data, B: Data) {
        try write(prompt: "A", line: A.hex)
        let s = try Data(hex: try read(label: "s"))
        let B = try Data(hex: try read(label: "B"))
        return (s, B)
    }

    /// Verify the user's response
    ///
    /// - Parameter M:
    /// - Returns: HAMK
    /// - Throws: on I/O Error
    func verify_session(M: Data) throws -> Data {
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
        let prompt = readprompt()
        guard prompt == "\(expectedPrompt): " else {
            throw RemoteError.unexpectedPrompt(prompt)
        }
        writeline(line)
    }

    private func writeline(_ line: String) {
        standardInput.fileHandleForWriting.write("\(line)\n".data(using: .ascii)!)
    }

    private func readprompt() -> String {
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

class PySRPTests: XCTestCase {
    func testSrptoolsServer() {
        do {
            let server = try RemoteServer(username: "bouke", password: "test")
            let client = Client(username: "bouke", password: "test")

            // The server generates the challenge: pre-defined salt, public key B
            // Server->Client: salt, B
            let (s, B) = try server.get_challenge(A: client.A)

            // Using (salt, B), the client generates the proof M
            // Client->Server: M
            let M = client.processChallenge(salt: s, B: B)

            // Using M, the server verifies the proof and calculates a proof for the client
            // Server->Client: H(AMK)
            let HAMK = try server.verify_session(M: M)

            // Using H(AMK), the client verifies the server's proof
            try client.verifySession(HAMK: HAMK)

            // At this point, the client is authenticated as well
            XCTAssert(client.isAuthenticated)

            // They now share a secret session key
            guard let K0 = try? server.get_session_key(), let K1 = client.sessionKey else {
                return XCTFail("Session keys not set")
            }
            XCTAssertEqual(K0, K1, "Session keys not equal")
        } catch {
            XCTFail("\(error)")
        }
    }

    static var allTests : [(String, (PySRPTests) -> () throws -> Void)] {
        return [
            ("testSrptoolsServer", testSrptoolsServer),
        ]
    }
}
