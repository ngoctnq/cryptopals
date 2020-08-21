# look mom, wildcard import
from utils import * #pylint:disable=unused-wildcard-import
import requests

def encryption_oracle_11(s: bytes) -> bytes:
    mode = 'ecb' if randint(0, 1) == 0 else 'cbc'
    s = generate_key(randint(5, 10)) + s + generate_key(randint(5, 10))
    s = pkcs7_pad(s)
    return AES_encrypt(generate_key(), s, mode), mode

random_key = generate_key()
unknown_string = b64decode(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
def encryption_oracle_12(s: bytes) -> bytes:
    s += unknown_string
    s = pkcs7_pad(s)
    return AES_encrypt(random_key, s, 'ecb')

random_length = randint(0, 100)
random_prefix = generate_key(random_length)
def encryption_oracle_14(s: bytes) -> bytes:
    s = random_prefix + s + unknown_string
    s = pkcs7_pad(s)
    return AES_encrypt(random_key, s, 'ecb')

def cookie2dict(s: str) -> dict:
    return dict(map(lambda x: x.split('='), s.strip('&').split('&')))

def dict2cookie(d: dict) -> str:
    # assume all k-v are strings
    return '&'.join(map('='.join, d.items()))

def profile_for(email: str):
    return dict2cookie({
        'email': email.replace('&', '').replace('=', ''),
        'uid': str(10),
        'role': 'user'
    })

random_key = generate_key()
# for the attacker
def encrypt_profile(email: str) -> bytes:
    s = profile_for(email).encode()
    s = pkcs7_pad(s)
    return AES_encrypt(random_key, s, 'ecb')

def decrypt_profile(s: bytes) -> dict:
    return cookie2dict(pkcs7_unpad(AES_decrypt(random_key, s, 'ecb')).decode())

random_key = generate_key()
def encrypt_data(s: str) -> bytes:
    s = r"comment1=cooking%20MCs;userdata=" + s.replace('=', '').replace(';', '') + r";comment2=%20like%20a%20pound%20of%20bacon"
    s = pkcs7_pad(s.encode())
    return AES_encrypt(random_key, s, 'cbc')

def is_admin(s: bytes) -> bool:
    return b'admin=true' in pkcs7_unpad(AES_decrypt(random_key, s, 'cbc')).split(b';')

###############
# BEGINS HERE #
###############

# challenge 9
assert pkcs7(b"YELLOW SUBMARINE", 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04"

# challenge 10
content = b64decode(requests.get('https://cryptopals.com/static/challenge-data/10.txt').text)
print(AES_decrypt(b'YELLOW SUBMARINE', content, 'cbc'))

# challenge 11
for _ in range(100):
    cipher, mode = encryption_oracle_11(b'a'* (16 * 3))
    if cipher[16:32] == cipher[32:48]:
        if mode != 'ecb':
            print('wrong')
    else:
        if mode != 'cbc':
            print('wrong')

# challenge 12
blocksize = 0
firstbreak = None
last_length = len(encryption_oracle_12(b'A' * blocksize))
while True:
    blocksize += 1
    new_length = len(encryption_oracle_12(b'A' * blocksize))
    if new_length != last_length:
        if firstbreak is None:
            firstbreak = blocksize
            last_length = new_length
        else:
            block_length = new_length - last_length
            block_count = len(encryption_oracle_12(b'')) // block_length
            print(block_length, block_count)
            blocksize = blocksize - firstbreak
            print(blocksize)
            break
print(brute_ecb_prepadding(encryption_oracle_12, block_count, blocksize, block_length))

# challenge 13
assert cookie2dict('foo=bar&baz=qux&zap=zazzle') == {
    'foo': 'bar',
    'baz': 'qux',
    'zap': 'zazzle'
}

assert dict2cookie({
    'foo': 'bar',
    'baz': 'qux',
    'zap': 'zazzle',
}) == 'foo=bar&baz=qux&zap=zazzle'

assert profile_for("foo@bar.com") == 'email=foo@bar.com&uid=10&role=user'

poison = encrypt_profile('A' * 10 + 'admin' + '\x0b' * 11)
user = encrypt_profile('bad@email.com')
crafted = user[:-16] + poison[16:32]
print(decrypt_profile(crafted))

# challenge 14
previous = encryption_oracle_14(b'')
idx = None
for i in range(1, 17):
    current = encryption_oracle_14(b'A' * i)
    # get index of first changing block
    if idx is None:
        idx = 0
        while True:
            if previous[idx * 16 : (idx + 1) * 16] != current[idx * 16 : (idx + 1) * 16]:
                break
            idx += 1
        print(idx)
    else:
        if previous[idx * 16 : (idx + 1) * 16] == current[idx * 16 : (idx + 1) * 16]:
            break
    previous = current
prefix_length = 16 * idx + 16 - i + (i % 16 > 0)

def surrogate_oracle(s: bytes) -> bytes:
    block_count = prefix_length // 16 + 1
    leftover = prefix_length % 16
    return encryption_oracle_14(b'A' * (16 - leftover) + s)[16 * block_count:]

print(brute_ecb_prepadding(surrogate_oracle, 9, 16))

# challenge 15
pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04")
pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05")

# challenge 16
cipher = encrypt_data('A' * 16)
bitflip = stream_xor(cipher[16:32],
            stream_xor(b'A' * 16, b"kwkt;admin=true;"))
print(is_admin(cipher[:16] + bitflip + cipher[16 * 2:]))