from binascii import unhexlify, hexlify
from base64 import b64encode, b64decode
from itertools import cycle, product
from string import printable
from math import log
from typing import Iterable
from Crypto.Cipher import AES
from random import randint
from typing import Optional, Callable
from tqdm import tqdm, trange

#########
# SET 1 #
#########

def hex2b64(hex_: hex) -> bytes:
    return b64encode(unhexlify(hex_))

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


