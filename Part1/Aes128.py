######## AES 128 implementation #############

def get_state(text):
    ret=[]
    barray=bytearray()
    for e in chunks(barray,16):
        ret.append(transpose_text(e,4))
    return ret

def extended_euclidean_algorithm(a,b):
    v=0
    u1=0
    u=1
    v1=1
    g=a
    g1=b
    while g1!=0:
        q=g/g1
        t1=u-q*u1
        t2=v-q*v1
        t3=g-q*g1
        u=u1
        v=v1
        g=g1
        u1=t1
        v1=t2
        g1=t3
    return (u,v,g)

def leftmost_bit(i):
    return i.bit_length()-1

def mult_poly(b1,b2):
    tmp1=b2;
    tmp2=b1
    ret=0
    while tmp1 != 0:
        tmp1=tmp1>>1
        tmp2=tmp2<<1
        ret=ret ^ ((tmp1 & 1) * (tmp2))
    return ret

def mod_poly(b1,m):
    res=b1
    while leftmost_bit(res) < 8:
        diff=leftmost_bit(res) - leftmost_bit(m)
        tmp=b1<<diff
        res=res ^ tmp
    return res

def inv_polynomial(p1):
    pass

def invmod(a,m):
    eea=extended_euclidean_algorithm(a,m)
    if eea[2] !=1:
        return 0
    else:
        return eea[0] % m


def compute_sbox():
    sbox=[]
    return sbox

def cipher(text):
    state=get_state

def shift_rows(state):
    pass
