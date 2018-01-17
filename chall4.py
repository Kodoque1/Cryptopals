#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      makkron
#
# Created:     13/08/2015
# Copyright:   (c) makkron 2015
# Licence:     <your licence>
#-------------------------------------------------------------------------------


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

os.chdir("C:\Users\makkron\Documents\Dev\Cryptopals")

_DECODE = lambda x, e: list(array('B', x.decode(e)))
_ENCODE = lambda x, e: join([chr(i) for i in x], '').encode(e)
HEX_TO_BYTES = lambda x: _DECODE(x, 'hex')
TXT_TO_BYTES = lambda x: HEX_TO_BYTES(x.encode('hex'))
BYTES_TO_HEX = lambda x: _ENCODE(x, 'hex')
BYTES_TO_TXT = lambda x: BYTES_TO_HEX(x).decode('hex')

def _pad(msg,additional):
	n = len(msg)
	bit_len = (n) * 8
	index = (bit_len >> 3) & 0x3fL
	pad_len = 120 - index
	if index < 56:
		pad_len = 56 - index
	padding = '\x80' + '\x00'*63

	padded_msg = msg + padding[:pad_len] + pack('<Q', bit_len+additional*8)
	return padded_msg

def _left_rotate(n, b):
	return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff

def _f(x, y, z): return x & y | ~x & z
def _g(x, y, z): return x & y | x & z | y & z
def _h(x, y, z): return x ^ y ^ z

def _f1(a, b, c, d, k, s, X): return _left_rotate(a + _f(b, c, d) + X[k], s)
def _f2(a, b, c, d, k, s, X): return _left_rotate(a + _g(b, c, d) + X[k] + 0x5a827999, s)
def _f3(a, b, c, d, k, s, X): return _left_rotate(a + _h(b, c, d) + X[k] + 0x6ed9eba1, s)

class MD4:

	def __init__(self,A = 0x67452301,B = 0xefcdab89,C = 0x98badcfe,D = 0x10325476):
		self.A = A
		self.B = B
		self.C = C
		self.D = D

	def update(self, message_string,additional):
		msg_bytes = TXT_TO_BYTES(_pad(message_string,additional))

		for i in range(0, len(msg_bytes), 64):
			self._compress(msg_bytes[i:i+64])

	def _compress(self, block):

		a, b, c, d = self.A, self.B, self.C, self.D

		x = []
		for i in range(0, 64, 4):
			x.append(unpack('<I', BYTES_TO_TXT(block[i:i+4]))[0])

		a = _f1(a,b,c,d, 0, 3, x)
		d = _f1(d,a,b,c, 1, 7, x)
		c = _f1(c,d,a,b, 2,11, x)
		b = _f1(b,c,d,a, 3,19, x)
		a = _f1(a,b,c,d, 4, 3, x)
		d = _f1(d,a,b,c, 5, 7, x)
		c = _f1(c,d,a,b, 6,11, x)
		b = _f1(b,c,d,a, 7,19, x)
		a = _f1(a,b,c,d, 8, 3, x)
		d = _f1(d,a,b,c, 9, 7, x)
		c = _f1(c,d,a,b,10,11, x)
		b = _f1(b,c,d,a,11,19, x)
		a = _f1(a,b,c,d,12, 3, x)
		d = _f1(d,a,b,c,13, 7, x)
		c = _f1(c,d,a,b,14,11, x)
		b = _f1(b,c,d,a,15,19, x)

		a = _f2(a,b,c,d, 0, 3, x)
		d = _f2(d,a,b,c, 4, 5, x)
		c = _f2(c,d,a,b, 8, 9, x)
		b = _f2(b,c,d,a,12,13, x)
		a = _f2(a,b,c,d, 1, 3, x)
		d = _f2(d,a,b,c, 5, 5, x)
		c = _f2(c,d,a,b, 9, 9, x)
		b = _f2(b,c,d,a,13,13, x)
		a = _f2(a,b,c,d, 2, 3, x)
		d = _f2(d,a,b,c, 6, 5, x)
		c = _f2(c,d,a,b,10, 9, x)
		b = _f2(b,c,d,a,14,13, x)
		a = _f2(a,b,c,d, 3, 3, x)
		d = _f2(d,a,b,c, 7, 5, x)
		c = _f2(c,d,a,b,11, 9, x)
		b = _f2(b,c,d,a,15,13, x)

		a = _f3(a,b,c,d, 0, 3, x)
		d = _f3(d,a,b,c, 8, 9, x)
		c = _f3(c,d,a,b, 4,11, x)
		b = _f3(b,c,d,a,12,15, x)
		a = _f3(a,b,c,d, 2, 3, x)
		d = _f3(d,a,b,c,10, 9, x)
		c = _f3(c,d,a,b, 6,11, x)
		b = _f3(b,c,d,a,14,15, x)
		a = _f3(a,b,c,d, 1, 3, x)
		d = _f3(d,a,b,c, 9, 9, x)
		c = _f3(c,d,a,b, 5,11, x)
		b = _f3(b,c,d,a,13,15, x)
		a = _f3(a,b,c,d, 3, 3, x)
		d = _f3(d,a,b,c,11, 9, x)
		c = _f3(c,d,a,b, 7,11, x)
		b = _f3(b,c,d,a,15,15, x)

		# update state
		self.A = (self.A + a) & 0xffffffff
		self.B = (self.B + b) & 0xffffffff
		self.C = (self.C + c) & 0xffffffff
		self.D = (self.D + d) & 0xffffffff

	def digest(self):
		return '%08x%08x%08x%08x' % (self.A, self.B, self.C, self.D)

def compute_padding(message):
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    # append the bit '1' to the message
    ret = b'\x80'
    # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
    #    is congruent to 448 (mod 512)
    ret += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    ret += struct.pack(b'>Q', original_bit_len)
    return ret



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

def decrypt(text,key):
    mode = AES.MODE_ECB
    encryptor = AES.new(key, mode)
    return encryptor.decrypt(text)

def chunks(l,n):
    for i in range(0,len(l),n):
        yield l[i:i+n]

def barray_to_string(text):
    return "".join(chr(i) for i in text)

def pkcs7(text,padding):
    tmp=padding - len(text)
    return text+tmp*chr(tmp)

def encrypt(text,key):
    mode = AES.MODE_ECB
    encryptor = AES.new(key, mode)
    return encryptor.encrypt(text)

def fixed_xor(h1,h2):
    res=bytearray()
    if len(h1) == len(h2):
        for i in range(0,len(h1)):
            res.append(h1[i] ^ h2[i])
    return res

#should take into account the fact that output may contains padding
def decrypt_CBC(text,key,IV):
    ret=""
    iterated_iv=bytearray(IV)
    tmp=chunks(text,16)
    for e in tmp:
        print ret
        ret=ret+barray_to_string(fixed_xor(bytearray(decrypt(barray_to_string(e),key)),iterated_iv))
        iterated_iv=e
    return ret

#It should  a 16 long padding at the end when length(text) % 16 =0
def encrypt_CBC(text,key,IVector):
    tmp=len(text)/16
    text=text[:(tmp)*16]+pkcs7(text[(tmp)*16:],16)
    mode=AES.MODE_CBC
    encryptor=AES.new(key, mode,IV=IVector)
    return encryptor.encrypt(text)

class CTR:
    def __init__(self):
        self.key=""
        for i in range(0,16):
            self.key=self.key+chr(random.randint(0,255))

    def encrypt(self,text):
        cipher=bytearray("".join([encrypt(self.key,8*"\x00"+chr(i)+7*"\x00") for i in range(0,len(text)/16 + 1)]))
        return fixed_xor(text,cipher[:len(text)])

    def rand_access(self,encrypted,offset,text):
        decrypted=self.encrypt(encrypted)
        tmp=decrypted[0:offset]+text+decrypted[offset+len(text):]
        return self.encrypt(tmp)

def break_rand_access_ctr(cipher,encrypted):
    dummy=bytearray(len(encrypted) * "A")
    tmp=cipher.rand_access(encrypted,0,dummy)
    key=fixed_xor(dummy,tmp)
    return fixed_xor(key,encrypted)

def challenge26():
    cipher=CTR()
    crypted=cipher.encrypt(bytearray(":admin<true"))
    crypted[0]=crypted[0] ^ 1
    crypted[6]=crypted[6] ^ 1
    return cipher.encrypt(crypted)

def c27_oracle(encrypted):
    decrypted=bytearray(decrypt_CBC(decrypted,key))
    for i in barray_to_string(decrypted):
        if ord(i) > 255:
            print "Error: High ASCII"
    return decrypted

#code won't work if the encrypt code is corrected
def challenge27():
    key=""
    for i in range(0,16):
        key=key+ chr(random.randint(0,255))
    print len(key)
    encrypted=encrypt_CBC(48*"X",key,key)
    test=encrypted[:16]+16*"\x00"+encrypted[:16]
    #here we will be able to recover the key by xoring the first and last of the result (0 middle block ensure that the first and last plaintext is the same)
    decrypted_attack=decrypt_CBC(bytearray(test),key,key) #suppose that the attacker does not have access to the key
    retrieved_key=fixed_xor(bytearray(decrypted_attack[:16]),bytearray(decrypted_attack[32:]))
    print retrieved_key
    print key
    print barray_to_string(retrieved_key) == key

def hmac_sha1(text,key):
    return sha1(key+text)

def hmac_md4(text,key):
    d=MD4()
    d.update(key+text,0)
    return d.digest()

def challenge29():
    key_length = random.randint(0,10)
    key="X" * key_length
    target_text="Coucou tout le monde"
    target_hash=hmac_sha1(target_text,key)
    h0=int(target_hash[:8],base=16)
    h1=int(target_hash[8:16],base=16)
    h2=int(target_hash[16:24],base=16)
    h3=int(target_hash[24:32],base=16)
    h4=int(target_hash[32:],base=16)
    attack_text="Evil hacker!"
    for counter in range(0,11):
        padding=compute_padding(counter*"a"+target_text)
        test_mac=hmac_sha1(target_text+padding+attack_text,key)
        attack_mac=sha1(attack_text,h0,h1,h2,h3,h4,counter+len(target_text)+len(padding))
        print attack_mac
        if attack_mac == test_mac:
            print "computed counter: " + str(counter)
            print "original length: " + str(key_length)

def challenge30():
    key_length = random.randint(0,10)
    key="X" * key_length
    target_text="Coucou tout le monde"
    target_hash=hmac_md4(target_text,key)
    h0=int(target_hash[:8],base=16)
    print h0
    h1=int(target_hash[8:16],base=16)
    h2=int(target_hash[16:24],base=16)
    h3=int(target_hash[24:32],base=16)

    attack_text="Evil hacker!"
    for counter in range(0,11):
        padded_text=_pad(counter*"a"+target_text,0)
        test_mac=hmac_md4(padded_text[counter:]+attack_text,key)
        d=MD4(h0,h1,h2,h3)
        print str(len(padded_text))
        d.update(attack_text,len(padded_text))
        attack_mac=d.digest()
        if attack_mac == test_mac:
            print "computed counter: " + str(counter)
            print "original length: " + str(key_length)

def main():
    pass

if __name__ == '__main__':
    main()
