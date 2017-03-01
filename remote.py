#!/usr/bin/env python

import argparse
import sys

from srptools import SRPContext, SRPServerSession, constants
from srptools.utils import value_encode

parser = argparse.ArgumentParser(description="SRP Server")
parser.add_argument("--group", default="N2048")  # todo: use prime (value) instead
parser.add_argument("--generator", default="02")  # hex
parser.add_argument("--algorithm", default="SHA1")
parser.add_argument("username")
parser.add_argument("password")
args = parser.parse_args()

groups = {
    "N2048": constants.PRIME_2048
}


def even_length_hex(hex):
    if len(hex) % 2 == 1:
        hex = "0" + hex
    return hex


context = SRPContext(args.username, args.password, prime=groups[args.group], generator=args.generator)
username, password_verifier, salt = context.get_user_data_triplet()

# Client => Server: username, A
sys.stdout.write("A: ")
sys.stdout.flush()
A = input()

# Receive username from client and generate server public.
server_session = SRPServerSession(context, password_verifier)

# Server => Client: s, B
print("s: " + even_length_hex(salt))
print("B: " + even_length_hex(server_session.public))

# Client => Server: M
sys.stdout.write("M: ")
sys.stdout.flush()
M = input()

# Process client public and verify session key proof.
server_session.process(A, salt)
assert server_session.verify_proof(M)

# Server => Client: HAMK
print("HAMK: " + even_length_hex(server_session.key_proof_hash))
print("K: " + even_length_hex(server_session.key))

