#!/usr/bin/env python
from __future__ import print_function

import argparse
from binascii import unhexlify
import sys

from srptools import SRPClientSession
from srptools import SRPContext, SRPServerSession, constants
from srptools.utils import hex_from, int_from_hex, value_encode

# Support Python 2 and 3
try: 
    input = raw_input
except NameError: 
    pass

def hex_encoded_utf8(value):
    return unhexlify(str.encode(value))

# 8192 bits prime is not a built-in prime in srptools,
# so a custom prime/generator is defined.
PRIME_8192_GEN = hex_from(19)
PRIME_8192 = '''\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8\
FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C\
180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D\
04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D\
B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226\
1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC\
E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26\
99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB\
04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2\
233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127\
D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492\
36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406\
AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918\
DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151\
2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03\
F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F\
BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA\
CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B\
B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632\
387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E\
6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA\
3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C\
5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9\
22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC886\
2F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6\
6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC5\
0846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268\
359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6\
FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71\
60C980DD98EDD3DFFFFFFFFFFFFFFFFF'''

groups = {
    "N1024": (constants.PRIME_1024, constants.PRIME_1024_GEN),
    "N1536": (constants.PRIME_1536, constants.PRIME_1536_GEN),
    "N2048": (constants.PRIME_2048, constants.PRIME_2048_GEN),
    "N3072": (constants.PRIME_3072, constants.PRIME_3072_GEN),
    "N4096": (constants.PRIME_4096, constants.PRIME_4096_GEN),
    "N6144": (constants.PRIME_6144, constants.PRIME_6144_GEN),
    "N8192": (PRIME_8192, PRIME_8192_GEN),
}

algorithms = {
    "sha1": constants.HASH_SHA_1,
    "sha256": constants.HASH_SHA_256,
}

ensure_hash_sizes = {
    "sha1": lambda hex: hex.zfill(40),
    "sha256": lambda hex: hex.zfill(64),
}

parser = argparse.ArgumentParser(description="SRP Server")
parser.add_argument("--group", default="N2048")
parser.add_argument("--algorithm", default="sha1")
parser.add_argument("--salt")
parser.add_argument("--private")

subparsers = parser.add_subparsers(dest="command")
subparsers.is_required = True
subparsers.add_parser("server")
subparsers.add_parser("client")

parser.add_argument("username", type=hex_encoded_utf8)
parser.add_argument("password", type=hex_encoded_utf8)

args = parser.parse_args()

prime = groups[args.group][0]
generator = groups[args.group][1]
hash_func = algorithms[args.algorithm]
ensure_hash_size = ensure_hash_sizes[args.algorithm]
context = SRPContext(args.username, args.password, prime=prime, generator=generator, hash_func=hash_func)

if args.command == "server":
    if args.salt:
        salt = args.salt
        password_verifier = value_encode(context.get_common_password_verifier(context.get_common_password_hash(unhexlify(salt))))
    else:
        _, password_verifier, salt = context.get_user_data_triplet()

    print("v:", password_verifier, file=sys.stderr)

    # Client => Server: username, A
    sys.stdout.write("A: ")
    sys.stdout.flush()
    A = input()

    # Receive username from client and generate server public.
    server_session = SRPServerSession(context, password_verifier, private=args.private)

    print("b:", server_session.private, file=sys.stderr)

    # Server => Client: s, B
    print("s:", salt)
    print("B:", server_session.public)

    # Client => Server: M
    sys.stdout.write("M: ")
    sys.stdout.flush()
    M = input()

    # Process client public and verify session key proof.
    server_session.process(A, salt)
    print("expected M:", server_session.key_proof, file=sys.stderr)

    assert server_session.verify_proof(M)

    # Server => Client: HAMK
    print("HAMK:", ensure_hash_size(server_session.key_proof_hash))

    # Always keep the key secret! It is printed to validate the implementation.
    print("K:", ensure_hash_size(server_session.key), file=sys.stderr)

if args.command == "client":
    client_session = SRPClientSession(context, private=args.private)
    print("a:", client_session.private, file=sys.stderr)

    # Client => Server: username, A
    print("A:", client_session.public)

    # Server => Client: s, B
    sys.stdout.write("s: ")
    sys.stdout.flush()
    s = input()
    sys.stdout.write("B: ")
    sys.stdout.flush()
    B = input()
    client_session.process(B, s)

    # Client => Server: M
    print("M:", ensure_hash_size(client_session.key_proof))

    # Server => Client: HAMK
    sys.stdout.write("HAMK: ")
    sys.stdout.flush()
    HAMK = input()
    assert client_session.verify_proof(HAMK)
    print("OK")

    # Always keep the key secret! It is printed to validate the implementation.
    print("K:", ensure_hash_size(client_session.key), file=sys.stderr)
