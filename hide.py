#!/usr/bin/env python3
'''
A simple, insecure symmetric encoding scheme for your files.

This is just designed to make it inconvenient for file hosts to read the file
as it originally was. This gives you at least a tiny bit of confidence that
your file host is not looking at your files, while giving you the confidence
that even if you lost this script to decode it, you can still do a brute force
to recover the original file.
'''

import argparse
from datetime import datetime
from hashlib import sha1
from typing import List
from itertools import cycle
from base64 import b64encode, b64decode

parser = argparse.ArgumentParser()
subs = parser.add_subparsers(dest='command')
parser_encode = subs.add_parser('encode')
parser_encode.add_argument('file', type=str)
parser_encode.add_argument('--year', type=int, default=datetime.now().year)

parser_decode = subs.add_parser('decode')
parser_decode.add_argument('file', type=str)
parser_decode.add_argument('--year', type=int, default=datetime.now().year)
parser_decode.add_argument('--output', type=str)

def xor_stream(data: bytes, key: bytes):
    key_iter = cycle(key)
    zipped = zip(data, key_iter)
    for data_byte, key_byte in zipped:
        yield data_byte ^ key_byte

def hash_year(year: int):
    return sha1(str(year).encode()).digest()

'''
Encode a file.

The encoding scheme is simple.

1) Take the year and turn it into a string.
2) Get the sha1 hash of that string. Convert into bytes.
3) For every byte in the file, xor it with the corresponding byte of the hash (looping the hash when necessary).
4) Convert to base64 and print.
'''
def encode(file: str, year: int):
    hashed_year = hash_year(year)
    with open(file, 'rb') as f:
        print(b64encode(bytearray(xor_stream(f.read(), hashed_year))).decode('UTF-8'))

def decode(file: str, year: int, out_file: str):
    hashed_year = hash_year(year)
    with open(file, 'r') as f, open(out_file, 'wb') as of:
        of.write(bytearray(xor_stream(b64decode(f.read()), hashed_year)))

if __name__ == '__main__':
    args = parser.parse_args()
    if args.command == 'encode':
        encode(args.file, args.year)
    elif args.command == 'decode':
        output = args.output
        if output is None:
            # Generate an output filename dependent on the input filename.
            output = args.file + '.decoded.bin'
        decode(args.file, args.year, output)
