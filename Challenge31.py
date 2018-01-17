#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      makkron
#
# Created:     21/08/2015
# Copyright:   (c) makkron 2015
# Licence:     <your licence>
#-------------------------------------------------------------------------------

#####
# Challenge 31()
import web
import time
import base64
import Crypto
import binascii
import os
import re
import random
from operator import itemgetter
from Crypto.Cipher import AES
from array import array
from string import join
from struct import pack, unpack
import struct

def _left_rotate(n, b):
	return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff

def sha1(message,h0 = 0x67452301,h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0, first_step_bit_len=0):
    """SHA-1 Hashing Function
    A custom SHA-1 hashing function implemented entirely in Python.
    Arguments:
        message: The input message string to hash.
    Returns:
        A hex SHA-1 digest of the input message.
    """
     # Pre-processing:
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    # append the bit '1' to the message
    message += b'\x80'

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
    #    is congruent to 448 (mod 512)
    message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)

    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    message += struct.pack(b'>Q', original_bit_len+ first_step_bit_len*8)

    # Process the message in successive 512-bit chunks:
    # break message into 512-bit chunks
    for i in range(0, len(message), 64):
        w = [0] * 80
        # break chunk into sixteen 32-bit big-endian words w[i]
        for j in range(16):
            w[j] = struct.unpack(b'>I', message[i + j*4:i + j*4 + 4])[0]
        # Extend the sixteen 32-bit words into eighty 32-bit words:
        for j in range(16, 80):
            w[j] = _left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)

        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            if 0 <= i <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid ~
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
                            a, _left_rotate(b, 30), c, d)

        # sAdd this chunk's hash to result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Produce the final hash value (big-endian):
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

def hmac_sha1(text,key):
    return sha1(key+text)

urls = (
  '/', 'index'
)

class index:
    def GET(self):
        key_length = random.randint(0,10)
        key="X" * key_length
        (f,signature)=web.input()
        h=hmac_sha1(f,key)
        for i in range(0,len(h)):
            if h[i] != signature:
                self.internalerror()
            time.sleep(0.05)
        return "Good one!"

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
