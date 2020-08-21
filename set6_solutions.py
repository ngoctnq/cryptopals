from rsa import (
    generate_keys,
    RSA_encrypt,
    invmod,
    int_to_bytes,
    pkcs15_pad,
    verify_pkcs1_padding,
    bleichenbacher_cca_rsa_pkcs1
)
from binascii import hexlify, unhexlify
import re, requests
from dsa import privkey_from_nonce, sign, verify, g, p, q
from sha1 import sha1
from utils import trange, b64decode
from io import BytesIO
import string
from math import ceil, floor
from fractions import Fraction

def chall41():
    N, e, d = generate_keys()
    s = 42
    # encrypt text
    encrypted = RSA_encrypt(s, N, e)
    # encrypt random
    enc2 = RSA_encrypt(69, N, e)
    # decrypt morphed
    dec2 = RSA_encrypt((encrypted * enc2) % N, N, d)
    # get original string
    decrypted = (dec2 * invmod(69, N)) % N
    assert s == decrypted

def chall42():
    while True:
        try:
            N, e, d = generate_keys(public_exp=3, prime_bitlength=1024)
            break
        except AssertionError:
            continue
    max_size = N.bit_length() // 8

    def sign_msg(msg):
        assert len(msg) == 40
        padded = b'0001' + b'ff' * (max_size - 20 - 3) + b'00' + msg
        return RSA_encrypt(int.from_bytes(unhexlify(padded), 'big'), N, d)

    def verify_msg(msg, cipher):
        assert len(msg) == 40
        res = hexlify(RSA_encrypt(cipher, N, e).to_bytes(max_size, 'big'))
        string = re.findall(rb'0001(?:ff)+00([0-9a-f]{40})', res)
        if len(string) == 0: return False
        return msg == string[0]

    hashed = sha1(b'hi mom').encode()
    signature = sign_msg(hashed)
    assert verify_msg(hashed, signature)

    # geometric search
    def cube_root_ceil(i: int) -> int:
        step_size = 1
        greed = True
        root = 1
        while True:
            ok = root ** 3 - i > 0
            if ok:
                if step_size == 1:
                    return root
                else:
                    step_size //= 2
                    root -= step_size
                    greed = False
            else:
                root += step_size
                if greed:
                    step_size *= 2

    # forging the signature
    padded = b'0001ff00' + hashed + b'0' * (max_size * 2 - 40 - 8)
    target = int.from_bytes(unhexlify(padded), 'big')
    forged = cube_root_ceil(target)
    assert verify_msg(hashed, forged)

def chall43():
    msg = b'For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n'
    pubkey = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    for k in trange(1, 2 ** 16 + 1):
        privkey = privkey_from_nonce(msg, (r, s), k)
        if pubkey == pow(g, privkey, p): break
    # check hash integrity
    assert sha1(hex(privkey)[2:].encode()) == '0954edd5e0afe5542a4adf012611a91912a3ec16'
    # check for signature
    hashed = int.from_bytes(unhexlify(sha1(msg)), 'big')
    r_ = pow(g, k, p) % q
    s_ = (invmod(k, q) * (hashed + privkey * r)) % q
    assert (r_, s_) == (r, s)

def chall44():
    pubkey = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
    lines = BytesIO(requests.get('https://cryptopals.com/static/challenge-data/44.txt').content)
    msgs = []
    rs = []
    ss = []
    ms = []
    for _ in range(11):
        msgs.append(lines.readline().lstrip(b'msg: ').strip(b'\n'))
        ss.append(int(lines.readline().lstrip(b's:')))
        rs.append(int(lines.readline().lstrip(b'r:')))
        ms.append(int(lines.readline().lstrip(b'm:'), 16))
        assert verify(msgs[-1], (rs[-1], ss[-1]), pubkey)
    # find which r is where
    pos = dict()
    for idx in range(11):
        r = rs[idx]
        if r not in pos:
            pos[r] = [idx]
        else:
            pos[r].append(idx)
            break
    assert len(pos[r]) == 2, 'No reused k found!'
    # get the nonce
    pos1, pos2 = pos[r]
    m1, m2 = ms[pos1], ms[pos2]
    s1, s2 = ss[pos1], ss[pos2]
    k = ((m1 - m2) % q * invmod((s1 - s2) % q, q)) % q
    # get the private key
    privkey = privkey_from_nonce(msgs[pos1], (r, s1), k)
    assert pubkey == pow(g, privkey, p)
    assert sha1(hex(privkey)[2:].encode()) == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'
    
def chall46():
    n, e, d = generate_keys(prime_bitlength=1024)
    def is_plaintext_even(cipher: int) -> bool:
        return bin(RSA_encrypt(cipher, n, d))[-1] == '0'
    secret = b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
    encrypted = RSA_encrypt(int.from_bytes(secret, 'big'), n, e)

    upper_bound = Fraction(n, 1)
    lower_bound = Fraction(0, 1)
    for i in trange(n.bit_length()):
        i += 1
        encrypted = (encrypted * pow(2, e, n)) % n
        if is_plaintext_even(encrypted):
            upper_bound = (upper_bound + lower_bound) / 2
        else:
            lower_bound = (upper_bound + lower_bound) / 2

    decrypted = int_to_bytes(int(upper_bound))
    assert decrypted == secret

def chall47_48(msg: bytes, modulus_bitsize: int):
    n, e, d = generate_keys(prime_bitlength=modulus_bitsize//2)
    m = pkcs15_pad(msg, modulus_bitsize//8)
    c = RSA_encrypt(int.from_bytes(m, 'big'), n, e)
    padding_oracle = lambda x: verify_pkcs1_padding(x, n, d)
    decrypted = int_to_bytes(bleichenbacher_cca_rsa_pkcs1(c, n, e, padding_oracle), modulus_bitsize)
    assert decrypted == m

# chall 47 has 256 as modulus bitsize, and chall 48 is 768.
# chall47_48(b'kwkt?', 64)
# chall47_48(b'kwkt desu', 128)
chall47_48(b'kick it, CC', 256)
# chall47_48(b'kick it, CC', 768)