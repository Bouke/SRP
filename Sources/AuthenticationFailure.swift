import Foundation

public enum AuthenticationFailure: Error {
    case invalidPublicKey
    case missingChallenge
    case keyProofMismatch
}

extension AuthenticationFailure: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidPublicKey: return "security breach - the provided public key was empty"
        case .missingChallenge: return "invalid client state - call `processChallenge` before `verifySession`"
        case .keyProofMismatch: return "failed authentication - the key proof didn't match our own"
        }
    }
}
