import CommonCrypto
import Foundation
import SRP

enum DataDecodingError: Error {
    case oddStringLength(Int)
}

extension Data {
    init(hex: String) throws {
        if hex.utf8.count % 2 == 1 {
            throw DataDecodingError.oddStringLength(hex.utf8.count)
        }
        let bytes = stride(from: 0, to: hex.utf8.count, by: 2)
            .map { hex.utf8.index(hex.utf8.startIndex, offsetBy: $0) }
            .map { hex.utf8[$0...hex.utf8.index(after: $0)] }
            .map { UInt8(String($0)!, radix: 16)! }
        self.init(bytes: bytes)
    }
    var hex: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

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

class Remote {
    private let process: Process

    private let standardOutput = Pipe()
    private var standardOutputBuffer = Data()

    private let standardInput = Pipe()
    private let standardError = Pipe()

    fileprivate init(process: Process) {
        self.process = process

        process.standardInput = standardInput
        process.standardOutput = standardOutput
        process.standardError = standardError

        process.launch()
    }


    fileprivate func write(prompt expectedPrompt: String, line: String) throws {
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

    fileprivate func read(label: String) throws -> (String) {
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

    fileprivate func error() -> RemoteError {
        let error = standardError.fileHandleForReading.readDataToEndOfFile()
        guard let message = String(data: error, encoding: .utf8) else {
            return RemoteError.commandFailure
        }
        return RemoteError.commandFailureWithMessage(message)
    }
}

class RemoteServer: Remote {
    init(group: Group = .N2048, alg: Digest = .SHA1, username: String, password: String) throws {
        guard let python = ProcessInfo.processInfo.environment["PYTHON"] else {
            throw RemoteError.noPython
        }

        let remotepy = URL(fileURLWithPath: #file)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("remote.py")

        let process = Process()
        process.launchPath = python
        process.arguments = [remotepy.path,
                             "server",
                             username,
                             password,
                             "--group", "\(group)",
                             "--algorithm", "\(alg)"]
        super.init(process: process)
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
}
