Secure Remote Password (SRP) for Swift
======================================

Secure Remote Password is a authentication protocol to prove your identity to
another party, using a password, but without ever revealing that password to
other parties. Not even the party you are proving your identity. See [Secure Remote Password protocol][5] for more information on this protocol.

![CI status](https://github.com/Bouke/SRP/workflows/Test/badge.svg)

## Example usage

```swift
// This is a database of users, along with their salted verification keys
let userStore: [String: (salt: Data, verificationKey: Data)] = [
    "alice": createSaltedVerificationKey(username: "alice", password: "password123"),
    "bob": createSaltedVerificationKey(username: "bob", password: "qwerty12345"),
]

// Alice wants to authenticate, she sends her username to the server.
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
let clientKeyProof = try client.processChallenge(salt: salt, publicKey: serverPublicKey)

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

More information can be found in the [documentation](http://boukehaarsma.nl/SRP).

## Swift Compatibility

Swift 4 is required with version 3 of this package. Use version 2 if you need 
Swift 3 compatibility.

## Compatibility with other implementations

I like to believe this implementation correctly implements the RFC.
However not all implementations do and might result in not being able to
authenticate accross implementations. And subtle differences might result in
low failure rates due to the randomness this protocol includes.

* Python: ❌ [srp][2] is not compatible; it doesn't correctly calculate `k`.
* Python: ✅ [srptools][3] is compatible.

## Development

### Testing

This project includes unit tests. A few compiler flags are required to run the tests swiftly:

    swift test -c release -Xswiftc -enable-testing

## References

* [RFC 2945 - The SRP Authentication and Key Exchange System][0]
* [RFC 5054 - Using the Secure Remote Password (SRP) Protocol for TLS Authentication][1]

## Credits

This library was written by [Bouke Haarsma][4].

[0]: https://tools.ietf.org/html/rfc2945
[1]: https://tools.ietf.org/html/rfc5054
[2]: https://pypi.python.org/pypi/srp
[3]: https://pypi.python.org/pypi/srptools
[4]: https://twitter.com/BoukeHaarsma
[5]: https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
