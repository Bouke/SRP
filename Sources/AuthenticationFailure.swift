import Foundation

/// Possible authentication failure modes.
public enum AuthenticationFailure: Error {
    /// Security breach: the provided public key is empty (i.e. PK % N is zero).
    case invalidPublicKey

    /// Invalid client state: call `processChallenge` before `verifySession`.
    case missingChallenge

    /// Failed authentication: the key proof didn't match our own.
    case keyProofMismatch
}

extension AuthenticationFailure: CustomStringConvertible {
    /// A textual representation of this instance.
    ///
    /// Instead of accessing this property directly, convert an instance of any
    /// type to a string by using the `String(describing:)` initializer.
    public var description: String {
        switch self {
        case .invalidPublicKey: return "security breach - the provided public key is invalid"
        case .missingChallenge: return "invalid client state - call `processChallenge` before `verifySession`"
        case .keyProofMismatch: return "failed authentication - the key proof didn't match our own"
        }
    }
}
