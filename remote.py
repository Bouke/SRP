#!/usr/bin/env python

import argparse
import binascii
import sys

import srp

parser = argparse.ArgumentParser(description="SRP Server")
parser.add_argument("--group", default="N2048")
parser.add_argument("--algorithm", default="SHA1")
parser.add_argument("username")
parser.add_argument("password")
args = parser.parse_args()

groups = {
    "N2048": srp.NG_2048
}
algorithms = {
    "SHA1": srp.SHA1
}

salt, vkey = srp.create_salted_verification_key(args.username, args.password, 
                                                hash_alg=algorithms[args.algorithm], 
                                                ng_type=groups[args.group])

# Client => Server: username, A
sys.stdout.write("A: ")
sys.stdout.flush()
A = binascii.unhexlify(raw_input())

svr = srp.Verifier(args.username, salt, vkey, A,
                   hash_alg=algorithms[args.algorithm], 
                   ng_type=groups[args.group])
s, B = svr.get_challenge()

# Server => Client: s, B
print "s: " + binascii.hexlify(s)
print "B: " + binascii.hexlify(B)

# Client => Server: M
sys.stdout.write("M: ")
sys.stdout.flush()
M = binascii.unhexlify(raw_input())

# Client => Server: M
HAMK = svr.verify_session(M)

if HAMK is None:
    print >>sys.stderr, 'error: could not verify session'
    exit(-1)

# Server => Client: HAMK
print "HAMK: " + binascii.hexlify(HAMK)

# At this point the authentication process is complete.
assert svr.authenticated()
print "K: " + srp.get_session_key()
