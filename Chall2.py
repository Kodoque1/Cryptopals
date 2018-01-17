#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      makkron
#
# Created:     26/07/2015
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

os.chdir("C:\Users\makkron\Documents\Dev\Cryptopals")

challenge_12_string="Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

def barray_to_string(text):
    return "".join(chr(i) for i in text)

def chunks(l,n):
    for i in range(0,len(l),n):
        yield l[i:i+n]

def fixed_xor(h1,h2):
    res=bytearray()
    if len(h1) == len(h2):
        for i in range(0,len(h1)):
            res.append(h1[i] ^ h2[i])
    return res

def pkcs7(text,padding):
    tmp=padding - len(text)
    return text+tmp*chr(tmp)

def decrypt(text,key):
    mode = AES.MODE_ECB
    encryptor = AES.new(key, mode)
    return encryptor.decrypt(text)

def decrypt_CBC(text,key,IV):
    ret=""
    iterated_iv=bytearray(IV)
    tmp=chunks(text,16)
    print iterated_iv
    for e in tmp:
        print ret
        ret=ret+barray_to_string(fixed_xor(bytearray(decrypt(barray_to_string(e),key)),iterated_iv))
        iterated_iv=e
    return ret

def challenge_10(f):
    with open(f) as myfile:
        data="".join([r.strip() for r in myfile])
    base=bytearray(base64.b64decode(data))
    print decrypt_CBC(base,"YELLOW SUBMARINE",16 * '0')

def encryption_oracle(text):
    key=""
    for i in range(0,16):
        key=key+chr(random.randint(0,255))
    mode=AES.MODE_ECB
    encryptor=AES.new(key, mode)
    rand_size=random.randint(5,10)
    rand_bytes=rand_size*chr(random.randint(0,255))
    text=rand_bytes+text+rand_bytes
    tmp=chunks(text,16)
    res=""
    block=0
    for e in tmp:
        padded=pkcs7(e,16)
        if random.randint(0,1):
            res=res+encryptor.encrypt(padded)
            print "ECB : " + str(block)
        else:
            iv=""
            for i in range(0,16):
                iv=iv+chr(random.randint(0,255))
            tmp=barray_to_string(fixed_xor(bytearray(padded),bytearray(iv)))
            res=res+encryptor.encrypt(tmp)
            print "CBC : " + str(block)
        block=block+1
    return res

def detect_mode(text,num):
    tmp=[]
    for i in range(0,len(text),16):
        tmp.append(text[i:i+16])
    block=tmp[num]
    tmp.pop(num)
    if block in tmp:
        return "ECB block"
    else:
        return "CBC block"

def challenge_12_encrypt(text,key):
    text=text+base64.b64decode(challenge_12_string)
    tmp=len(text)/16
    text=text[:(tmp)*16] +pkcs7(text[(tmp)*16:],16)
    mode=AES.MODE_ECB
    encryptor=AES.new(key, mode)
    return encryptor.encrypt(text)

def detect_block_size(encrypt,key):
    blocksize=1
    test_input=blocksize*"A"
    bs_test=encrypt(test_input,key)
    blocksize=2
    while True:
        test_input=blocksize*"A"
        bs_test_n=encrypt(test_input,key)
        if bs_test_n[:blocksize-1] == bs_test :
            return blocksize-1
        bs_test=bs_test_n[:blocksize]
        blocksize=blocksize+1

def challenge_12(encrypt):
    key=""
    for i in range(0,16):
        key=key+chr(random.randint(0,255))
    bs=detect_block_size(encrypt,key)
    print "passed detection, bs:" +str(bs)
    print detect_mode(encrypt(2*bs*"A",key),0)
    res=""
    for i in range(1,bs):
        d={}
        dummy=encrypt((bs-i)*"A",key)[:16]
        test_string=(bs-i)*"A"+res
        for j in range(0,255):
            d[encrypt(test_string+chr(j),key)[:16]]=chr(j)
        #print d[dummy]
        res=res+d[dummy]
    return res

def parse_kv(obj):
    d={}
    tmp=obj.split("&")
    print tmp
    for i in tmp:
        s=i.split("=")
        d[s[0]]=s[1]
    return d

def profile_for(text):
    tmp=text.split("&")[0].split("=")
    return tmp[0]+"&uid=10&role=user"

def challenge_13_oracle(text,key):
    tmp=profile_for(text)
    div=len(tmp)/16
    tmp=tmp[:(div)*16] +pkcs7(tmp[(div)*16:],16)
    mode=AES.MODE_ECB
    encryptor=AES.new(key, mode)
    return encryptor.encrypt(tmp)

#challenge 13
def challenge_13():
    key=""
    for i in range(0,16):
        key=key+chr(random.randint(0,255))
    admin_block=challenge_13_oracle("foo",key)[0:16]
    admin_block_2=challenge_13_oracle(pkcs7("admin",16),key)[0:16]
    mail=challenge_13_oracle("A"*16,key)[0:16]
    text=mail+admin_block+admin_block_2
    final=decrypt(text,key)
    return final[:-ord(final[-1])]

def challenge_14_encrypt(rand_bytes,text,key):

    text=rand_bytes+text+base64.b64decode(challenge_12_string)
    tmp=len(text)/16
    text=text[:(tmp)*16]+pkcs7(text[(tmp)*16:],16)
    mode=AES.MODE_ECB
    encryptor=AES.new(key, mode)
    return encryptor.encrypt(text)

def compute_comp_and_pos(rand_bytes,key,encrypt):
    #Compute a sentry that will allow us to know that the oracle is under good condition to do our detection
    for i in range(0,16):
        dummy=i*"A"+32*"B"
        tmp=encrypt(rand_bytes,dummy,key)
        print tmp
        #print len(tmp)
        for j in range(0,len(tmp)-1,16):
            if tmp[j:j+16] == tmp[j+16:j+32]:
                return (i,j)

def challenge_14(encrypt):
    rand_size=random.randint(0,50)
    rand_bytes=rand_size*chr(random.randint(0,255))
    key=""
    for i in range(0,16):
        key=key+chr(random.randint(0,255))
    res=""
    (rand_complement,pos)=compute_comp_and_pos(rand_bytes,key,encrypt)
    #we already know that cyphering is in EBC mode and that the key is 128
    res=""
    for i in range(1,16):
        d={}
        dummy=encrypt(rand_bytes,rand_complement*"A"+(16-i)*"A",key)[pos:pos+16]
        test_string=rand_complement*"A"+(16-i)*"A"+res
        for j in range(0,255):
            d[encrypt(rand_bytes,test_string+chr(j),key)[pos:pos+16]]=chr(j)
        #print d[dummy]
        res=res+d[dummy]
    return res

def unpack_pkcs7(text):
    if len(text)==16:
        c=text[-1]
        if int(c.encode("hex"),base=16) < 16:
            return text[:text.find(c)]

def challenge_15_oracle(nada,text,key):
    text="comment1=cooking%20MCs;userdata="+text.strip(";").strip("=")+";comment2=%20like%20a%20pound%20of%20bacon"
    tmp=len(text)/16
    text=text[:(tmp)*16]+pkcs7(text[(tmp)*16:],16)
    mode=AES.MODE_CBC
    encryptor=AES.new(key, mode,IV=16 * '\x00'  )
    return encryptor.encrypt(text)

def challenge_15(encrypt):
    key=""

    for i in range(0,16):
        key=key+chr(random.randint(0,255))
    #(rand_complement,pos)=compute_comp_and_pos("",key,encrypt)
    (rand_complement,pos)=(0,32)
    dummy=rand_complement*"A"+":admin<true"
    tmp=encrypt("",dummy,key)
    block=tmp[pos-16:pos]
    print "passed"
    print block
    c1=block[6]
    print "passed"
    c2=block[0]
    nblock=chr(ord(c2)^1)+block[1:6]+chr(ord(c1)^1)+block[7:]
    print len(nblock)
    attempt=bytearray(tmp[:pos-16]+nblock+tmp[pos:])
    print len(attempt)
    return decrypt_CBC(attempt,key,16*'0')


def main():

    pass

if __name__ == '__main__':
    main()
