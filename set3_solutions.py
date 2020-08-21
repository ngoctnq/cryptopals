from utils import * #pylint:disable=unused-wildcard-import
from random import choice, seed
import requests

# challenge 17
def chall17():
    strings = [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ]
    random_key = generate_key()

    def random_encrypt() -> (bytes, bytes):
        random_string = pkcs7_pad(b64decode(choice(strings)))
        iv = generate_key()
        cipher = AES_encrypt(random_key, random_string, 'cbc', iv)
        return cipher, iv

    def check_padding(cipher: bytes, iv: bytes) -> bool:
        plain = AES_decrypt(random_key, cipher, 'cbc', iv)
        try:
            pkcs7_unpad(plain)
            return True
        except AssertionError:
            return False

    cipher, iv = random_encrypt()
    print(pkcs7_unpad(padding_oracle_attack(cipher, check_padding, iv)))

def chall18():
    return encrypt_ctr(
        b"YELLOW SUBMARINE",
        b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    )

def chall19():
    strings = [
        'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
        'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
        'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
        'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
        'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
        'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
        'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
        'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
        'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
        'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
        'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
        'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
        'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
        'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
        'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
        'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
        'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
        'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
        'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
        'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
        'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
        'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
        'U2hlIHJvZGUgdG8gaGFycmllcnM/',
        'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
        'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
        'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
        'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
        'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
        'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
        'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
        'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
        'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
        'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
        'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
        'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
        'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
        'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
        'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
        'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
        'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='
    ]
    
    seed('no random')
    random_key = generate_key()
    encrypted = [encrypt_ctr(random_key, b64decode(s)) \
        for s in strings]

    stream_len = max(map(len, encrypted))
    # we'll update this
    keystream = [0] * stream_len
    for i in range(stream_len):
        cipher = bytes([x[i] for x in encrypted if len(x) > i])
        # we'll just guess these later
        if len(cipher) < 2:
            continue
        _, key, _ = brute_xor(cipher, c_max=1)
        keystream[i] = key[0]

    keystream[0] ^= ord('N') ^ ord('I')
    keystream[25] ^= ord('f') ^ ord('g')
    keystream[27] ^= 0x01 ^ ord(' ')
    keystream[31] ^= ord('!') ^ ord(' ')
    keystream[32] ^= ord('I') ^ ord('d')
    keystream[34] ^= ord('Q') ^ ord('a')
    keystream[35] ^= ord('e') ^ ord('d')
    keystream[36] ^= ord('Y') ^ ord('n')
    keystream[37] ^= 0x0c ^ ord(',')
    
    keystream = bytes(keystream)
    for cipher in encrypted:
        print(stream_xor(cipher, keystream))

def chall22():
    from mersenne_twister import seed_mt, get_random_number
    from time import time

    def routine():
        seed_val = int(time()) + randint(40, 1000)
        seed_mt(seed_val)
        return get_random_number(), seed_val

    current_time = int(time())
    random_number, seed_val = routine()

    # create some slack on max rand to make up for code execution time
    for i in range(2000):
        new_seed = current_time + i
        seed_mt(new_seed)
        if get_random_number() == random_number:
            break
    
    assert new_seed == seed_val

def chall23():
    from time import time
    from mersenne_twister import seed_mt, get_random_number, untemper, create_generator

    seed_mt(int(time()))
    # throw away some value
    for _ in range(123): get_random_number()
    # tap for 624 values
    rands = [get_random_number() for i in range(624)]

    # custom MT states
    generator = create_generator([untemper(r) for r in rands])

    # check if the next 1000 numbers are the same
    for _ in range(1000):
        assert get_random_number() == next(generator)

chall23()