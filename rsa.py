from Crypto.Util.number import getPrime
from random import randint
from typing import Callable
from math import floor, ceil
from fractions import Fraction
from bisect import bisect
from utils import egcd, invmod, chinese_remainder

def generate_key(public_exp: int = 65537,
                  prime_bitlength: int = 2048
                 ) -> (int, int, int):
    # returns N, e, d
    p = getPrime(prime_bitlength)
    q = getPrime(prime_bitlength)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = invmod(public_exp, phi)
    return n, public_exp, d

def RSA_encrypt(s: int, N: int, e: int = 65537) -> int:
    # s is the text to be encrypted
    # similar to CTR, both needs only one function
    return pow(s, e, N)

def int_to_bytes(s: int, bit_length=None) -> bytes:
    bit_length = bit_length or s.bit_length()
    return int.to_bytes(s, (bit_length + 7) // 8, 'big')

def pkcs15_pad(s: bytes, length: int) -> bytes:
    randlen = length - 3 - len(s)
    assert randlen >= 0, "Message longer than targeted length."
    return b'\x00\x02' + bytes([randint(1, 255) for _ in range(randlen)]) + b'\x00' + s

def verify_pkcs1_padding(cipher: int, n: int, d: int) -> bool:
        decrypted = int_to_bytes(RSA_encrypt(cipher, n, d), n.bit_length())
        return decrypted[0] == 0 and decrypted[1] == 2 # and b'\x00' in decrypted[2:]

def bleichenbacher_cca_rsa_pkcs1(c: int,
                                 n: int,
                                 e: int,
                                 padding_oracle: Callable[[int], bool]
                                ) -> bytes:
    # skipping step 1 because cipher is already pkcs1.5-conforming
    i = 1
    Blog2 = (n.bit_length() - 9) // 8 * 8
    B = (1 << Blog2)
    M = [[2 * B, 3 * B - 1]]
    while True:
        # step 2a
        if i == 1:
            s = ceil(Fraction(n >> Blog2, 3))
            while True:
                if padding_oracle((c * pow(s, e, n)) % n):
                    break
                else:
                    s += 1
        # step 2b
        elif len(M) > 1:
            s += 1
            while True:
                if padding_oracle((c * pow(s, e, n)) % n):
                    break
                else:
                    s += 1
        # step 2c
        else:
            a, b = M[0]
            rn = ceil(Fraction(2 * (b * s - 2 * B), n)) * n
            lower = ceil(Fraction(2 * B + rn, b))
            upper = floor(Fraction(3 * B + rn, a))
            s = lower
            while True:
                if padding_oracle((c * pow(s, e, n)) % n):
                    break
                if s < upper:
                    s += 1
                else:
                    rn += n
                    lower = ceil(Fraction(2 * B + rn, b))
                    upper = floor(Fraction(3 * B + rn, a))
                    s = lower
        # step 3
        new_M = []
        for a, b in M:
            lower = a * s - 3 * B + 1
            upper = b * s - 2 * B
            rn = ceil(Fraction(lower, n)) * n
            while rn <= upper:
                new_pair = [max(a, ceil(Fraction(2 * B + rn, s))),
                            min(b, floor(Fraction(3 * B - 1 + rn, s)))]
                # let's not merge if I don't have to -- one less thing to debug
                # for pair in new_M:
                #     assert pair[1] < new_pair[0] or pair[0] > new_pair[1], 'You need to merge intervals!'
                new_M.append(new_pair)
                # # merge the subintervals
                # idx = bisect(new_M, new_pair)
                # if idx > 0 and new_M[idx - 1][1] >= new_pair[0]:
                #     new_M[idx - 1][1] = new_pair[1]
                #     idx -= 1
                # else: new_M.insert(idx, new_pair)
                # new_idx = bisect(new_M, [new_pair[1] + 1, 0])
                # new_M[idx][1] = max(new_M[idx][1], new_M[new_idx - 1][1])
                # del new_M[idx + 1:new_idx]
                rn += n
        M = new_M
        # step 4
        if len(M) == 1 and M[0][0] == M[0][1]:
            return M[0][0]
        else: i += 1
