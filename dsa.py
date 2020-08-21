from Crypto.Util.number import getPrime
from random import randrange
from sha1 import sha1
from rsa import invmod
from utils import unhexlify

# from the problem
p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

def generate_keys() -> (int, int):
    privkey = randrange(1, q)
    pubkey = pow(g, privkey, p)
    return pubkey, privkey

def sign(msg: bytes, privkey: int) -> (int, int):
    hashed = int.from_bytes(unhexlify(sha1(msg)), 'big')
    while True:
        k = randrange(1, q)
        r = pow(g, k, p) % q
        if r == 0: continue
        s = (invmod(k, q) * (hashed + privkey * r)) % q
        if s == 0: continue
        return (r, s)#, k

def verify(msg: bytes, signature: (int, int), pubkey: int) -> bool:
    r, s = signature
    if not (0 < r < q and 0 < s < q): return False
    w = invmod(s, q)
    hashed = int.from_bytes(unhexlify(sha1(msg)), 'big')
    u1 = (hashed * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(pubkey, u2, p)) % p) % q
    return v == r

def privkey_from_nonce(msg: bytes, signature: (int, int), nonce: int) -> int:
    r, s = signature
    hashed = int.from_bytes(unhexlify(sha1(msg)), 'big')
    return ((s * nonce - hashed) * invmod(r, q)) % q

if __name__ == '__main__':
    pubkey, privkey = generate_keys()
    text = b'ngoctnq'
    signature = sign(text, privkey)
    assert verify(text, signature, pubkey)
    # assert privkey_from_nonce(text, signature, nonce) == privkey
