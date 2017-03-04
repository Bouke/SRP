Secure Remote Password (SRP) for Swift
======================================

SRP6 for Swift. API designed similar to the Python packages [srp][2] and [srptools][3].

[![Build Status](https://travis-ci.org/Bouke/SRP.svg?branch=master)](https://travis-ci.org/Bouke/SRP)

## Example usage

```swift
// This is a database of users, along with their salted verification keys
let userStore: [String: (salt: Data, verificationKey: Data)] = [
    "alice": createSaltedVerificationKey(username: "alice", password: "password123"),
    "bob": createSaltedVerificationKey(username: "alice", password: "qwerty12345"),
]

// Alice wants to authenticate, it sends her username to the server.
let client = Client(username: "alice", password: "password123")
let (username, clientPublicKey) = client.startAuthentication()

let server = Server(
    username: username,
    salt: userStore[username]!.salt,
    verificationKey: userStore[username]!.verificationKey)

// The server shares Alice's salt and its public key (the challenge).
let (salt, serverPublicKey) = server.getChallenge()

// Alice generates a sessionKey and proofs she generated the correct
// session key based on her password and the challenge.
let clientKeyProof = client.processChallenge(salt: salt, publicKey: serverPublicKey)

// The server verifies Alices' proof and generates their proof.
let serverKeyProof = try server.verifySession(publicKey: clientPublicKey, keyProof: clientKeyProof)

// The client verifies the server's proof.
try client.verifySession(keyProof: serverKeyProof)

// At this point, authentication has completed.
assert(server.isAuthenticated)
assert(client.isAuthenticated)

// Both now have the same session key. This key can be used to encrypt
// further communication between client and server.
assert(server.sessionKey == client.sessionKey)
```

## References

* [RFC 2945 - The SRP Authentication and Key Exchange System][0]
* [RFC 5054 - Using the Secure Remote Password (SRP) Protocol for TLS Authentication][1]

[0]: https://tools.ietf.org/html/rfc2945
[1]: https://tools.ietf.org/html/rfc5054
[2]: https://pypi.python.org/pypi/srp
[3]: https://pypi.python.org/pypi/srptools
