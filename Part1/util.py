#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      makkron
#
# Created:     25/05/2015
# Copyright:   (c) makkron 2015
# Licence:     <your licence>
#-------------------------------------------------------------------------------
import base64
import binascii
import os
import re
from operator import itemgetter

os.chdir("C:\Users\makkron\Documents\Dev\Cryptopals\Part1")

translation_table=['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X','Y', 'Z', 'a', 'b', 'c',
'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o','p', 'q', 'r', 's',
't', 'u', 'v', 'w', 'x', 'y', 'z','0', '1', '2', '3', '4', '5', '6', '7', '8', '9','+', '/']

english_top_frequency={'a':8.12, 'e':12.02, 'i':7.31,'o':7.68,'u':3,'t':9.10,'n':6.95,'s':6.28,
'r':6.02,'h':5.92,'d':4.32,'l':3.98,'u':2.88,'c':2.71,'m':2.61,'f':2.30,'y':2.11,'w':2.09,'g':2.03,'p':1.82,'b':1.49,'v':1.11,'k':0.69,'x':0.17,'q':0.11,'j':0.10,'z':0.07}

def chunks(l,n):
    for i in range(0,len(l),n):
        yield l[i:i+n]

def to_bit(h):
    return bin(int(h, base=16))[2:].zfill(4)

def to_int(b):
    return int(b,base=2)

def shex(b):
    return hex(b)[2:]

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

def hex_to_b64(h):
    triple=0
    buf="" # will store the three bytes
    res="" # will store the result
    for e in h:

        if triple==3:
            a=buf[0:6]
            b=buf[6:12]
            c=buf[12:18]
            d=buf[18:]
            res=res+translation_table[to_int(a)]+translation_table[to_int(b)]+translation_table[to_int(c)]+translation_table[to_int(d)]
            triple=0
            buf=""
            buf=buf+to_bit(i)
        else:
            triple=triple+1
    if triple != 0:
        buf=buf + (3-triple) * '0000'
        a=buf[0:6]
        b=buf[6:12]
        c=buf[12:18]
        d=buf[18:24]
        res=translation_table[to_int(a)]+translation_table[to_int(b)]+translation_table[to_int(c)]+translation_table[to_int(d)]
    return res

def b64_to_hex(b):
    res=""
    div=len(b) / 4
    #loop each 4 characters
    for i in range(0,div-1):
        tmp=b[i*4:(i+1)*4]
        r=""
        #building 24 bits string
        for c in tmp:
            ind=bin(translation_table.index(c))[2:].zfill(6)
            #print ind
            r=r+ind
        #extracting the 6 hex number
        for i in range(0,6):
            #print r[i*4:(i+1)*4]
            res+=hex(int(r[i*4:(i+1)*4],base=2))[2:]
    #process last base64 symbol
    tmp=b[(div-1)*4:]
    print tmp
    num_eq=tmp.count("=")
    if num_eq !=0:
        tmp=tmp[:-num_eq]
        print tmp
        r=""
        for c in tmp:
            ind=bin(translation_table.index(c))[2:].zfill(6)
            #print ind
            r=r+ind
            #extracting the 6 hex number
        for i in range(0,6-2*num_eq):
            #print r[i*4:(i+1)*4]
            res+=hex(int(r[i*4:(i+1)*4],base=2))[2:]
    return res

def hex_to_b64_2(h):
    res=""
    barray=bytearray.fromhex(h)
    mod=len(barray) % 3
    for e in chunks(barray,3):
        tmp="".join([bin(i)[2:].zfill(8) for i in e])
        for e2 in chunks(tmp,6):
            #print int(("".join(e2)).zfill(6))
            res=res+translation_table[int(("".join(e2)).zfill(6),base=2)]
    return res+(3-mod)*"="

def fixed_xor(h1,h2):
    res=bytearray()
    if len(h1) == len(h2):
        for i in range(0,len(h1)):
            res.append(h1[i] ^ h2[i])
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

def detect_single_keys(file):
    f=open(file)
    score=100000
    for l in f.readlines():
        r=break_keys(l.strip("\n"))
        tmp=r['score']
        if tmp < score :
            score=tmp
            res=r
    return res

def repeating_key_xor(text,key):
    print text
    len_key=len(key)
    len_text=len(text)
    r=len_text%len_key
    d=len_text/len_key
    full_key=bytearray(key)*d + bytearray(key)[0:r]
    #full_key=bytearray([binascii.b2a_hex("c") for i in range(0,length)])
    return fixed_xor(text,full_key)

def hamming(s1,s2):
    #input string? no hex!
    tmp = "".join(hex(i)[2:] for i in fixed_xor(s1,s2))
    print "tmp : " + tmp
    return bin(int(tmp, base=16)).count("1")

def compute_keysize(text):
    keysizes=[]
    print text
    for i in range(2,10):
        part1=text[0:i]
        part2=text[i:2*i]
        part3=text[2*i:3*i]
        part4=text[3*i:4*i]
        #print part1
        #print part2
        sc1=hamming(part1,part2)/float(8*i)
        sc2=hamming(part3,part4)/float(8*i)
        score=(sc1+sc2)/float(2)
        #print tmp
        keysizes.append((score,i))
    print sorted(keysizes,key=itemgetter(0))
    return sorted(keysizes,key=itemgetter(0))

def transpose_text(text, keysize):
    cut=[]
    div=len(text) / keysize
    for i in range(0,div):
        cut.append(text[i * keysize:(i+1)*keysize])
    res=[]
    for i in range (0,keysize):
        tmp=[]
        for r in cut:
            tmp.append(r[i])
        res.append(bytearray(tmp))
    return res

def break_repeating_key_xor(t):
    print t
    text=bytearray.fromhex(t)
    print text
    keysizes=compute_keysize(text)
    ret=[]
    for k in keysizes:
        transpose=transpose_text(text,k[1])
        res=""
        for e in transpose:
            tmp=break_keys(e)
            res=res+tmp["char"]
            #print tmp["text"]
        ret.append(res)
    return ret

def challenge_6(f):
    #Break vigenere crypto
    with open(f) as myfile:
        data="".join(line.rstrip() for line in myfile)
    base=b64_to_hex(data)
    print base
    keys = break_repeating_key_xor(base)
    for k in keys:
        print "Key :" + k
        print "".join(chr(i) for i in repeating_key_xor(bytearray.fromhex(base),k))

def challenge_7(f,key):
    with open(f) as myfile:
        data="".join(line.rstrip() for line in myfile)
    base=base64.b64decode(data)
    tmp=len(base) % 16
    print decrypt_AES128(base,key)

def decrypt_AES128(text,key):
    IV = 16 * '\x00'           # Initialization vector: discussed later
    mode = AES.MODE_ECB
    encryptor = AES.new(key, mode)
    return encryptor.decrypt(text)

def challenge_8(f):
    with open(f) as myfile:
        for l in myfile.readlines():
            l=l.rstrip()
            if len(l) % 32 == 0:
                for i in range(0,len(l),32):
                    tmp=l[0:i]+l[i+32:]
                    if l[i:i+32] in tmp:
                        print "ECB detect : " + l
                        break
def main():
    test = hex_to_b64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    assert (test=="SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

if __name__ == '__main__':
    main()
