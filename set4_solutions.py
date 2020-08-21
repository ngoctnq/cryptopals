from utils import * #pylint:disable=unused-wildcard-import
import requests
from tqdm import trange
from random import seed

def chall25():
    text = AES_decrypt(b'YELLOW SUBMARINE', b64decode(requests.get('https://cryptopals.com/static/challenge-data/25.txt').text))
    random_key = generate_key()
    keystream = encrypt_ctr(random_key, b'\x00' * len(text))
    cipher = stream_xor(text, keystream)
    
    # API exposed to hacker
    def edit(offset: int, newtext: bytes) -> int:
        return cipher[:offset] + \
               stream_xor(newtext, keystream[offset:offset + len(newtext)]) + \
               cipher[offset + len(newtext):]
    
    # decrypt byte-by-byte
    plaintext = b''
    for i in trange(len(cipher)):
        for b in range(256):
            byte = bytes([b])
            if edit(i, byte) == cipher:
                plaintext += byte
                break
    print(plaintext)

def chall26():
    random_key = generate_key()
    def encrypt_data(s: str) -> bytes:
        s = r"comment1=cooking%20MCs;userdata=" + s.replace('=', '').replace(';', '') + r";comment2=%20like%20a%20pound%20of%20bacon"
        return encrypt_ctr(random_key, s.encode())

    def is_admin(s: bytes) -> bool:
        return b'admin=true' in encrypt_ctr(random_key, s).split(b';')

    cipher = encrypt_data('A' * 16)
    cipher = cipher[:32] + stream_xor(b'A' * 16,
        stream_xor(b'kwkt;admin=true;', cipher[32:48])
    ) + cipher[48:]
    assert is_admin(cipher)

def chall27():
    seed('no_random')
    random_key = generate_key()
    def encrypt_data(s: str) -> bytes:
        s = r"comment1=cooking%20MCs;userdata=" + s.replace('=', '').replace(';', '') + r";comment2=%20like%20a%20pound%20of%20bacon"
        return AES_encrypt(random_key, pkcs7_pad(s.encode()), 'cbc', random_key)

    def is_admin(s: bytes) -> bool:
        decrypted = pkcs7_unpad(AES_decrypt(random_key, s, 'cbc', random_key)).split(b';')
        for char in decrypted:
            assert int(char) <= 127, decrypted
        return b'admin=true' in decrypted

    # 3 blocks
    cipher = encrypt_data('')
    # will raise error
    is_admin(cipher[:16] + b'\x00' * 16 + cipher[:16] + cipher[48:])

    decrypted = b'comment1=cooking\x86H\xf5\xd6\xcf\xc6uG\r\xc0J\xf5/\xb5\x1c\nV)\x08\xc5\x89\xed\x82\xddi\x01\x86\xd3\xb4s\xd9\xfc\x1en\x80\xc2\x8d(\xe1\xc9\xed\xea\x0e\xe6\xc6\x87\xec\xa2of%20bacon'
    recovered = stream_xor(decrypted[:16], decrypted[32:48])
    assert recovered == random_key

from sha1 import sha1
def sha1_hmac(msg: bytes) -> hex:
    return sha1(b'secret' + msg)

def chall29():

    import struct
    def sha1_pad(msg: bytes):
        pad = b'\x80'

        # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
        # is congruent to 56 (mod 64)
        pad += b'\x00' * ((56 - (len(msg) + 1) % 64) % 64)

        # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
        pad += struct.pack(b'>Q', len(msg) * 8)
        return msg + pad

    from sha1 import Sha1Hash
    prefix_len = 6

    # original HMAC
    original_data = rb"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    hmac = sha1_hmac(original_data)

    # pad data while prefixing with some dummy bytes
    padded_data = sha1_pad(b'A' * prefix_len + original_data)

    # forged HMAC
    hasher = Sha1Hash()
    hasher._h = [int(hmac[i : i + 8], 16) for i in range(0, 40, 8)]
    hasher._message_byte_length = len(padded_data)
    forged = hasher.update(b';admin=true').hexdigest()

    # HMAC with admin flag
    new_hmac = sha1_hmac(padded_data[prefix_len:] + b';admin=true')

    assert forged == new_hmac        

def chall30():
    from md4 import MD4
    import struct

    def md4_hmac(msg: bytes) -> bytes:
        return MD4(b'secret' + msg).hexdigest()
    
    def md4_pad(msg: bytes) -> bytes:
        ml = len(msg) * 8
        msg += b"\x80"
        msg += b"\x00" * (-(len(msg) + 8) % 64)
        msg += struct.pack("<Q", ml)
        return msg
    
    prefix_len = 6

    # original HMAC
    original_data = rb"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    hmac = md4_hmac(original_data)

    # pad data while prefixing with some dummy bytes
    padded_data = md4_pad(b'A' * prefix_len + original_data)

    # forged HMAC
    hasher = MD4()
    hasher.h = list(struct.unpack("<4I", hmac))
    hasher.count = len(padded_data) // 64
    forged = hasher.update(b';admin=true').hexdigest()

    # HMAC with admin flag
    new_hmac = md4_hmac(padded_data[prefix_len:] + b';admin=true')

    assert forged == new_hmac      

def chall31():

    def candidate2hex(candidate):
        return ''.join(hex(c)[-1] for c in candidate)

    def check_hash(candidate):
        # candidate is 20 bytes in a list
        hash_ = candidate2hex(candidate)
        res = [
            requests.get('http://localhost:9000/test', {
            'file': 'vierundzwanzigsieben',
            'signature': hash_
            }) for _ in range(10)
        ]
        return res[0].ok, sum([x.elapsed.total_seconds() for x in res]) / len(res)

    # candidate = [0] * 40
    # idx = 0
    candidate = [int(x, 16) for x in '7bcc5cb74c9cded322af7a50409a9c10dd3f0000']
    idx = 36
    last_elapsed = None
    while True:
        res, elapsed = check_hash(candidate)
        if res:
            print('Correct hash found:', candidate2hex(candidate))
            break
        if candidate[idx] == 0:
            next_candidate = candidate[:idx] + [1] + [0] * (39 - idx)
            res_, elapsed_ = check_hash(next_candidate)

            if res_:
                print('Correct hash found:', candidate2hex(next_candidate))
                break

            if abs(elapsed_ - elapsed) < 3e-3:
                last_elapsed = elapsed_
                candidate[idx] = 2
            elif elapsed_ < elapsed:
                if idx < 39:
                    last_elapsed = elapsed
                    idx += 1
                else:
                    idx -= 1
            else:
                if idx < 39:
                    last_elapsed = elapsed_
                    candidate[idx] = 1
                    idx += 1
                else:
                    idx -= 1
        
        else:
            if elapsed > last_elapsed + 3e-3:
                last_elapsed = elapsed
                if idx < 39:
                    idx += 1
                # false positive, try again
                else:
                    candidate[idx] = 0

            elif elapsed < last_elapsed - 3e-3:
                if idx < 39:
                    candidate[idx] -= 1
                    idx += 1
                # false positive, try again
                else:
                    candidate[idx] = 0
                    idx -= 1
                    candidate[idx] = 0

            # try twice
            elif candidate[idx] == 31:
                candidate[idx] = 0
                if idx > 0:
                    idx -= 1
                    candidate[idx] = 0
            else:
                last_elapsed = elapsed
                candidate[idx] += 1

chall30()