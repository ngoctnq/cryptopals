from binascii import unhexlify, hexlify
from base64 import b64encode, b64decode
from itertools import cycle, product
from string import printable
from math import log, ceil
from typing import Iterable
from Crypto.Cipher import AES
from random import randint
from typing import Optional, Callable
from tqdm import tqdm, trange
import re, requests

#########
# SET 1 #
#########

def stream_xor(b1: bytes, b2: bytes) -> bytes:
    # will repeat b2 (the key) if needed.
    return bytes(x ^ y for x, y in zip(b1, cycle(b2)))

def is_printable(s: bytes) -> bool:
    return len(set(s) - set(printable.encode())) == 0

# from http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
ENGLISH_FREQ = {
    'A' :  8.55,        'K' :  0.81,        'U' :  2.68,
    'B' :  1.60,        'L' :  4.21,        'V' :  1.06,
    'C' :  3.16,        'M' :  2.53,        'W' :  1.83,
    'D' :  3.87,        'N' :  7.17,        'X' :  0.19,
    'E' : 12.10,        'O' :  7.47,        'Y' :  1.72,
    'F' :  2.18,        'P' :  2.07,        'Z' :  0.11,
    'G' :  2.09,        'Q' :  0.10,                 
    'H' :  4.96,        'R' :  6.33,                 
    'I' :  7.33,        'S' :  6.73,                 
    'J' :  0.22,        'T' :  8.94,    
}

def get_score(s: bytes,
              replace: bool = True,
              puncts: Iterable[bytes] = b',. \'"\n'
             ) -> float:
    '''
    Get the log likelihood of an English string.

    Parameters:
        @s          bytestring to be considered
        @replace    whether to not count valid punctuations in freq analysis
        @puncts     the punctuations to consider
                    only required when `replace` is True

    Effectively, remove punctuations from the strings, so that the normalizing
    constant is smaller in that case, prioritizing strings with more printables.
    '''
    if replace:
        for b in puncts:
            if type(b) is int:
                b = chr(b).encode()
            s = s.replace(b, b'')
    return sum(ENGLISH_FREQ[char] * (log(s.count(char.encode()) + s.count(char.lower().encode()) + 1e-12) - log(len(s))) \
        for char in ENGLISH_FREQ)

def brute_xor(cipher: bytes,
              c_min: int = 1,
              c_max: int = 4,
              charset: Iterable[bytes] = range(256)
             ) -> (int, bytes, bytes):
    '''
    Parameters:
        @cipher     cipher to be decrypted
        @c_min      the min length of XOR key
        @c_max      the max length of XOR key
        @charset    the character set of the key
    Output:
        @max_score  the maximum likelihood
        @key        the key used to decrypt
        @decrypted  the decrypted text
    Note: this function runs sequentially.
    Should be easily modified to run in parallel.
    '''
    max_score, max_decrypted, max_key = None, None, None
    for c_len in range(c_min, c_max + 1):
        for key in product(charset, repeat=c_len):
            # broken bytestring
            if type(key[0]) is int:
                key = bytes(key)
            # literal list of bytes
            # helpful when you're trying only a fixed set of possible keys
            else:
                key = b''.join(key)
            decrypted = stream_xor(cipher, key)
            score = get_score(decrypted)
            if max_score is None or score > max_score:
                max_score, max_decrypted, max_key = score, decrypted, key
    return max_score, max_key, max_decrypted

def hamming(str1: bytes, str2: bytes) -> int:
    assert len(str1) == len(str2)
    diff = 0
    for x, y in zip(str1, str2):
        # in case this is an array of bytes instead of a bytestring
        if type(x) is not int:
            x = ord(x)
        if type(y) is not int:
            y = ord(y)
        diff += sum(map(int, bin(x ^ y)[2:]))
    return diff

def break_repeated_xor(cipher: bytes,
                       min_keysize=2,
                       max_keysize=40,
                      ) -> (bytes, bytes):
    '''
    Returns:
        @key        the guessed key
        @decrypted  the decrypted text with that key
    '''
    min_distance, _min_keysize = None, None
    for keysize in range(min_keysize, max_keysize + 1):
        # we take (max) 4 blocks and get the one with minimum average edit distance
        block_count = min(len(cipher) // keysize, 4)
        blocks = []
        for i in range(block_count):
            blocks.append(cipher[i * keysize : (i + 1) * keysize])
        distance = 0
        for i in range(block_count):
            for j in range(i, block_count):
                distance += hamming(blocks[i], blocks[j])
        distance /= (keysize * block_count * (block_count - 1) / 2)
        if min_distance is None or min_distance > distance:
            min_distance, _min_keysize = distance, keysize
    
    key = b''
    for i in range(_min_keysize):
        _, keychar, _ = brute_xor(cipher[i::_min_keysize], c_max=1)
        key += keychar
    
    return key, stream_xor(cipher, key)

#########
# SET 2 #
#########

def pkcs7(s: bytes, length: int) -> bytes:
    assert 0 <= length < 256
    return s + bytes([length] * length)

def pkcs7_pad(s: bytes) -> bytes:
    return pkcs7(s, 16 - (len(s) % 16))

def pkcs7_unpad(s: bytes) -> bytes:
    assert s[-s[-1]:] == s[-1:] * s[-1]
    return s[:-s[-1]]

def AES_decrypt(key: bytes,
                cipher: bytes,
                mode: Optional[str] = 'ecb',
                iv: Optional[bytes] = b'\x00' * 16,
                nonce: Optional[int] = 0
               ) -> bytes:
    # nonce only needed if mode is 'ctr'
    if mode == 'ctr':
        return encrypt_ctr(key, cipher, iv, nonce)

    cryptor = AES.new(key, AES.MODE_ECB)
    decrypted = b''
    for i in range(0, len(cipher), 16):
        decrypted += stream_xor(cryptor.decrypt(cipher[i : i + 16]), iv)
        if mode == 'cbc':
            iv = cipher[i : i + 16]
    return decrypted

def AES_encrypt(key: bytes,
                plain: bytes,
                mode: Optional[str] = 'ecb',
                iv: Optional[bytes] = b'\x00' * 16,
                nonce: Optional[int] = 0
               ) -> bytes:
    # nonce only needed if mode is 'ctr'
    if mode == 'ctr':
        return encrypt_ctr(key, plain, iv, nonce)

    cryptor = AES.new(key, AES.MODE_ECB)
    encrypted = b''
    for i in range(0, len(plain), 16):
        last_block = cryptor.encrypt(stream_xor(plain[i : i + 16], iv))
        encrypted += last_block
        if mode == 'cbc':
            iv = last_block
    return encrypted

def generate_key(length: int = 16) -> bytes:
    # NOT cryptographically secure!
    return bytes([randint(0, 255) for _ in range(length)])

def brute_ecb_prepadding(oracle: Callable[[bytes], bytes],
                         block_count: int,
                         block_length: int,
                         cipher_length: Optional[int] = None
                        ) -> bytes:
    '''
    This bruteforces any AES-ECB encrypted string, given that we can
    choose any arbitrary string to prepend the secret string before encryption.

    Parameters:
        @oracle         takes in the prepending string, returns the ciphertext
        @block_count    number of blocks of the secret text
        @block_length   length of each encryption block
        @cipher_length  length of each encrypted block (note the difference)
    '''
    if cipher_length is None:
        cipher_length = block_length
    length = block_count * block_length
    found = []
    for _ in trange(length):
        payload = b'A' * (length - len(found) - 1)
        truth = oracle(payload)[:block_count * cipher_length]
        for b in range(256):
            if oracle(payload + bytes(found + [b])).startswith(truth):
                found.append(b)
                break
    return bytes(found)

#########
# SET 3 #
#########

def padding_oracle_attack_block(cipher: bytes,
                                oracle: Callable[[bytes, bytes], bool],
                                iv: bytes
                                ) -> bytes:
    ret = b''
    for i in range(16):
        prefix = iv[:-i-1]
        if i == 0:
            postfix = b''
        else:
            postfix = stream_xor(stream_xor(ret, iv[-i:]),
                                 bytes([i + 1] * (i + 1)))
        for candidate in range(256):
            iv_ = prefix + bytes([candidate]) + postfix
            if not oracle(cipher, iv_):
                continue
            # wiggle to make sure that it is indeed 0x01 (instead of 0x0202)
            if i == 0:
                iv_ = prefix[:-1] + bytes([(prefix[-1] + 1) % 256, candidate])
                if not oracle(cipher, iv_):
                    continue
            ret = chr(candidate ^ (i + 1) ^ iv[- i - 1]).encode() + ret
            break
    return ret

def padding_oracle_attack(cipher: bytes,
                          oracle: Callable[[bytes, bytes], bool],
                          iv: Optional[bytes] = b'\x00' * 16
                         ) -> bytes:
    ret = b''
    for i in range(len(cipher) // 16):
        block = cipher[i * 16 : i * 16 + 16]
        ret += padding_oracle_attack_block(block, oracle, iv)
        iv = block
    return ret

def encrypt_ctr(key: bytes,
                cipher: bytes,
                iv: Optional[bytes] = b'\x00' * 8,
                nonce: Optional[int] = 0
               ) -> bytes:
    # 64 bit (8 byte) IV, 64 bit CTR, Little Endian (reverse)
    ret = b''
    for i in range(0, len(cipher), 16):
        block = cipher[i : i + 16]
        real_iv = (unhexlify(f'{nonce:016x}') + iv)[::-1]
        ret += stream_xor(block, AES_encrypt(key, real_iv, 'ecb'))
        nonce += 1
    return ret

#########
# SET 8 #
#########

def egcd(m: int, n: int) -> (int, (int, int)):
    # return gcd(m, n) = mx + ny in this order: (gcd(m, n), (x, y))
    assert m > 0 and n > 0, "Parameters to `egcd` must be positive."
    m_coeff = (1, 0)
    n_coeff = (0, 1)
    if m < n:
        m, n = n, m
        m_coeff, n_coeff = n_coeff, m_coeff

    while True:
        r, q = divmod(m, n)
        if q == 0:
            return n, n_coeff
        m, n = n, q
        # q = m - n * r
        m_coeff, n_coeff = n_coeff, tuple(map(lambda x: x[0] - r * x[1], zip(m_coeff, n_coeff)))

def invmod(n: int, p: int) -> int:
    '''Returns the modular inverse under Zp.'''
    # assure positivity
    n %= p

    g, (x, _) = egcd(n, p)
    assert g == 1, 'Can only invmod on mutually prime numbers.'
    return x % p

def invmod_prime(n: int, p: int) -> int:
    # p has to be prime
    n %= p
    return pow(n, p - 2, p)

def chinese_remainder(moduli, remainders):
    ''' Chinese remainder theorem
    Returns the remainder and the grand modulus.
    '''
    residue = 0
    prod = 1
    for modulus in moduli: prod *= modulus
    for modulus, remainder in zip(moduli, remainders):
        prod_ = prod // modulus
        inverse = invmod(prod_, modulus)
        residue = (residue + remainder * inverse * prod_) % prod
    return residue, prod

def jacobi_symbol(n: int, p: int):
    assert n > 0 and p > 0, 'Parameters to Jacobi symbol must be positive!'
    assert p % 2, 'p must be odd.'
    sign = 1
    while True:
        if p == 1: return sign
        n %= p
        if n == 0: return 0
        even_invert = (p % 8) in (3, 5)
        while n & 1 == 0:
            if even_invert:
                sign = -sign
            n >>= 1
        if n == 1: return sign
        if n % 4 == 3 and p % 4 == 3:
            sign = -sign
        n, p = p, n

def sqrtmod(n: int, p: int) -> int:
    ''' Tonelli-Shanks algorithm '''
    # find q, s such that q2^s = p-1
    q = p-1
    s = 0
    while q & 1 == 0:
        s += 1
        q >>= 1
    # get a quadratic non-residue
    for z in range(1, p):
        if jacobi_symbol(z, p) == -1:
            break
    # let
    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) >> 1, p)
    # loop
    while True:
        if t == 0: return 0
        if t == 1: return r
        t2i = t
        for i in range(1, m):
            t2i = pow(t2i, 2, p)
            if t2i == 1: break
        else:
            return None
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = (t * c) % p
        r = (r * b) % p

def ceil_root(i: int, rootexp: int) -> int:
    ''' ceiling of root using geometric search '''
    step_size = 1
    greed = True
    root = 1
    while True:
        ok = root ** rootexp - i > 0
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

def bsgs(y, g, n, p):
    '''
    Baby step - Giant step aka Shank's algorithm to find discrete log
    Params:
        @y  point to find the discrete log
        @g  generator of the Abelian group
        @n  order of the group/generator
        @p  the GF(p) we're working with
    '''
    m = ceil_root(n, 2)
    hashtable = dict()
    for j in range(m):
        hashtable[pow(g, j, p)] = j
    
    invm = pow(g, p - 1 - m, p)
    gamma = y
    for i in range(m):
        if gamma in hashtable:
            return i * m + hashtable[gamma]
        y = (y * invm) % p


def pohlig_hellman(y: int, g: int, p: int, order: dict, parallel=False):
    if len(order) == 1:
        x = 0
        for p, e in order.items(): pass
        order = p ** e
        gamma = pow(g, p ** (e - 1), p)
        for k in range(e):
            h = pow(y * pow(g, order - x, p), e - 1 - k, p)
            d = bsgs(h, gamma, order, p)
            x = (x + d * pow(p, k, order)) % order
    else:
        params = []
        order = 1
        for p, e in order.items():
            order *= p ** e
        factors = []
        for p, e in order.items():
            factor = p ** e
            power = order // factor
            factors.append(factor)
            gi = pow(g, power, p)
            yi = pow(y, power, p)
            params.append([yi, gi, p, {p: e}])
        if parallel:
            from multiprocessing import Pool, cpu_count
            remainders = Pool(cpu_count()).starmap(pohlig_hellman, params)
        else:
            from itertools import starmap
            remainders = starmap(pohlig_hellman, params)
        remainders = list(remainders)
        return chinese_remainder(factors, remainders)[0]
    

'''
def factorize_factordb(p: int) -> dict:
    result = requests.get(f'http://factordb.com/index.php?query={p}').text
    status = re.search(r'\WFF\W', result)
    print(result)
    # if not found
    if status is None: return None
    ret = {}
    pattern = r'<a href="index.php\?id=\d+"><font color="#000000">((?:\d[\d.]+)?\d)(?:\^(\d+))?<\/font><\/a>'
    for match in re.finditer(pattern, result):
        xp, mult = match.groups()
        print(xp, mult)
        if '.' in xp: return None
        ret[int(xp)] = int(mult or 1)
    return ret

# print(factorize_factordb(1231241242110259458797201845670243391072241213131236761817460))
'''