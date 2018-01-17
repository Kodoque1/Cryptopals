#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      makkron
#
# Created:     30/07/2015
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

def barray_to_string(text):
    return "".join(chr(i) for i in text)

english_top_frequency={'a':8.12, 'e':12.02, 'i':7.31,'o':7.68,'u':3,'t':9.10,'n':6.95,'s':6.28,
'r':6.02,'h':5.92,'d':4.32,'l':3.98,'u':2.88,'c':2.71,'m':2.61,'f':2.30,'y':2.11,'w':2.09,'g':2.03,'p':1.82,'b':1.49,'v':1.11,'k':0.69,'x':0.17,'q':0.11,'j':0.10,'z':0.07}

challenge17_strings=[
"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93]",
]

def compute_frequency(text):
    fdict={}
    for e in text:
        c=e.lower()
        if(c in fdict.keys()):
            fdict[c]=fdict[c]+1
        else:
            fdict[c]=0
    length_of_text=len(text)
    for c in fdict.keys():
        fdict[c]=(fdict[c]/float(length_of_text)) * 100.
    #print fdict
    return fdict

def compare_f_english(text):
    fdict=compute_frequency(text)
    sum=0
    for c in fdict.keys():
        if c in english_top_frequency.keys():
            #print "fdict : " + str(fdict[c])
            #print abs(english_top_frequency[c]-fdict[c])
            sum=sum+abs(english_top_frequency[c]-fdict[c])
        else:
            if c not in [" ","'"]:
                sum=sum+20 # not sure
    # when no keys is available
    return sum

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

def encrypt(text,key):
    mode = AES.MODE_ECB
    encryptor = AES.new(key, mode)
    return encryptor.encrypt(text)

def decrypt(text,key):
    mode = AES.MODE_ECB
    encryptor = AES.new(key, mode)
    return encryptor.decrypt(text)

def decrypt_CBC(text,key,IV):
    ret=""
    iterated_iv=bytearray(IV)
    tmp=chunks(text,16)
    for e in tmp:
        #print "iterated iv: " + iterated_iv
        #print "e : " + str(len(e))
        ret=ret+barray_to_string(fixed_xor(bytearray(decrypt(e,key)),bytearray(iterated_iv)))
        iterated_iv=e
    return ret

def encrypt_CBC(text,key,IV):
    ret=""
    iterated_iv=bytearray(IV)
    tmp=chunks(text,16)
    print len(text)
    for e in tmp:
        #print e
        #print iterated_iv
        iterated_iv=encrypt(barray_to_string(fixed_xor(bytearray(e),bytearray(iterated_iv))),key)
        ret=ret+iterated_iv
    print len(ret)
    return ret

def encrypt_CTR(text,key):
    cipher=bytearray("".join([encrypt(key,8*"\x00"+chr(i)+7*"\x00") for i in range(0,len(text)/16 + 1)]))
    print len(text)
    print len(cipher[:len(text)])
    return fixed_xor(text,cipher[:len(text)])

def encrypt_c17(key):
    len_input=len(challenge17_strings)
    text=challenge17_strings[random.randint(0,len_input-1)]
    mod=len(text) % 16
    if mod == 0:
        text=text+16*chr(16)
    else:
        text=text[:-mod]+pkcs7(text[-mod:],16)
        print len(text)
    return encrypt_CBC(text,key,16*"\x00")

def test_pad_c17(text):
    #print "padding test :" + text
    c=text[-1]
    #print c.encode("hex")
    padding_size=int(c.encode("hex"),base=16)
    #print padding_size
    if (0<padding_size) and (padding_size<=16):
        for i in range(1,padding_size+1):
            if text[-i] != c:
                return False
        return True
    else:
        return False

def decrypt_c17(text,key):
    ret=decrypt_CBC(text,key,16*"0")
    #print ret
    return test_pad_c17(ret[-16:])

def break_block(encrypted,pos,key):
    clear_block=""
    print encrypted[pos]
    for i in range(1,17):
        for c in range(0,256):
            #print "clear_block length:" + str(len(clear_block))
            #print "character : " + chr(c)
            #print "size : " + str(i)
            modified=(16-i)*"A"+"".join(chr(e) for e in fixed_xor(bytearray(chr(c)+clear_block),bytearray(chr(i)*i)))
            #print modified
            modified=barray_to_string(fixed_xor(bytearray(modified),bytearray(encrypted[pos-1])))
            #print "modified length:" + str(len(modified))
            tmp=modified+encrypted[pos]
            #print "length tmp : " + str(len(tmp))
            #print modified
            #print len(tmp)
            if decrypt_c17(tmp,key):
                clear_block=chr(c)+clear_block
                #print clear_block
                break
    return clear_block

def unpack_pkcs7(text):
    if len(text)==16:
        c=text[-1]
        if int(c.encode("hex"),base=16) < 16:
            return text[:text.find(c)]

def challenge_17():
    key=""
    for i in range(0,16):
        key=key+chr(random.randint(0,255))
    encrypted_text=encrypt_c17(key)
    print [encrypted_text]
    print [i for i in chunks(encrypted_text,16)]
    list_of_block=[16*"\x00"] + [i for i in chunks(encrypted_text,16)]
    return "".join([break_block(list_of_block,idx,key) for idx in range(1,len(list_of_block))])

def open_and_decode(f):
    ret=[]
    with open(f) as myfile:
        for l in myfile:
            ret.append(base64.b64decode(l))
    return ret

def transpose_text_c20(text, keysize):
    print "reached"
    res=[]
    for i in range (0,keysize):
        tmp=bytearray()
        for r in text:
            tmp.append(r[i])
        res.append(tmp)
    return res

def break_keys(text):
    #half_length_of_text=len(text)/2
    length=len(text)
    score=100000
    selected_char='a'
    selected_text=""
    for c in range(0,255):
        key=bytearray([c for i in range(0,length)])
        decrypted="".join(chr(i) for i in fixed_xor(text,key))
        #tmp=compare_f_english(re.sub(r'\W+','',decrypted))
        tmp=compare_f_english(decrypted)
        #if tmp<10000:
        if tmp < score :
        #if c=="x" :
            score = tmp
            selected_char=chr(c)
            selected_text=decrypted
    return {"text":selected_text,"char":selected_char,"score":score,"original":text}

def statistical_break_c20(f):
    tmp=open_and_decode(f)
    key="".join([chr(random.randint(0,256)) for i in range(0,16)])
    encrypted_list=[encrypt_CTR(bytearray(t),"".join(key)) for t in test]
    smallest_text=min([len(e) for e in encrypted_list])
    tmp1=[e[:smallest_text] for e in encrypted_list]
    transpose=transpose_text_c20(tmp1,smallest_text)
    res=""
    for e in transpose:
        tmp3=break_keys(e)
        res=res+tmp3["char"]
        #print tmp["text"]
    print res
    print [barray_to_string(fixed_xor(e,bytearray(res))) for e in tmp1]

def _int32(s):
    return 0xffffffff & s

def _int8(s):
    return 0xff & s

class mt199337:

    def __init__(self,seed):
        self.index=624
        self.state = [0] * 624
        self.state[0]=seed
        for i in range(1,624):
            self.state[i] = (_int32(1812433253 * (self.state[i-1] ^ (self.state[i-1] >> (30)))) + i)

    def extract_number(self):
        #tempering_transform
        if self.index >= 624:
            self.twist()

        y = self.state[self.index]

        # Right shift by 11 bits
        y = y ^ y >> 11
        # Shift y left by 7 and take the bitwise and of 2636928640
        y = y ^ y << 7 & 2636928640
        # Shift y left by 15 and take the bitwise and of y and 4022730752
        y = y ^ y << 15 & 4022730752
        # Right shift by 18 bits
        y = y ^ y >> 18
        self.index = self.index + 1
        return _int32(y)

    def twist(self):
        for i in range(0,624):
            y = _int32((self.state[i] & 0x80000000) + (self.state[(i + 1) % 624] & 0x7fffffff))
            self.state[i] = self.state[(i + 397) % 624] ^ y >> 1

            if y % 2 != 0:
                self.state[i] = self.state[i] ^ 0x9908b0df
        self.index=0

    def splice(self,state):
        self.state=list(state)
        self.index=624

def challenge22():
    time.sleep(random.randint(40,1000))
    target_seed=int(time.time())
    mt=mt199337(target_seed)
    compare_rand=mt.extract_number()
    time.sleep(random.randint(40,1000))
    test_time=int(time.time())
    print "Testing..."
    for i in range(test_time-2000,test_time):
        tmp=mt199337(i)
        test_rand=tmp.extract_number()
        if test_rand == compare_rand:
            print "seed found :" + str(i) +", original: " + str(target_seed)
            break

def cancel_s_a(y,shift,constant):
    print "orginal : \n" + bin(y)
    for i in range(shift,32,shift):
        mask = int((shift*'1' +i*'0').zfill(32),base=2)
        y = y ^ ( (y << shift & constant) & mask)
        print bin(y)
    return y

def cancel_s(y,shift):
    print "orginal : \n" + bin(y)
    for i in range(shift,32,shift):
        mask = int((shift*'1'+(32-i)*'0'),base=2)
        print "mask: " + bin(mask)
        print i
        y = y ^ ( (y >> shift) & mask)
        print bin(y)
    tmp= 32 % shift
    mask = int(tmp*'1',base=2)
    print bin(mask)
    y = y ^ ( (y >> shift) & mask)
    return y

def invert_tempering(y):
    y = cancel_s(y,18)
    y=cancel_s_a(y,15,4022730752)
    y=cancel_s_a(y,7,2636928640)
    y = cancel_s(y,11)
    return y

def test_tempering(y):
     print bin(y)
     y = y ^ y >> 11
        # Shift y left by 7 and take the bitwise and of 2636928640
     y = y ^ y << 7 & 2636928640
        # Shift y left by 15 and take the bitwise and of y and 4022730752
     y = y ^ y << 15 & 4022730752
        # Right shift by 18 bits
     y = y ^ y >> 18

     y=invert_tempering(y)
     return y

def challenge23(mt):
    sub_state=[]
    for i in range(0,624):
        sub_state.append(invert_tempering(mt.extract_number()))
    ret=mt199337(0)
    ret.splice(sub_state)
    return ret

def encrypt_MT19337(seed,barray):
    mt=mt199337(seed)
    # Building cipher
    return [ t ^ _int8(mt.extract_number()) for t in barray]

def break_mt_cipher(barray):
    r=len(barray)-14
    print "size of rest: " + str(r)
    for seed in range(0, 2**16):
        mt=mt199337(seed)
        for i in range(0,r):
            mt.extract_number()
        v1=chr(_int8(mt.extract_number()) ^ barray[r])
        v2=chr(_int8(mt.extract_number()) ^ barray[r+1])
        if v1 == 'a' and v2 == 'a':
            return seed
    return -1

def challenge_24_part1():
    buf=""
    for i in range(0,random.randint(0,10)):
        buf=buf+chr(random.randint(0,255))
    print "size of random string :" + str(len(buf))
    buf=buf + 14 * 'a'
    print buf
    crypted=encrypt_MT19337(31337,bytearray(buf))
    return break_mt_cipher(crypted)

def main():
    pass

if __name__ == '__main__':
    main()
