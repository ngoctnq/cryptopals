from utils import * #pylint:disable=unused-wildcard-import
import requests

# challenge 1
def hex2b64(hex_: hex) -> bytes:
    return b64encode(unhexlify(hex_))
assert hex2b64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d') \
        == b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    
# challenge 2
assert stream_xor(unhexlify('1c0111001f010100061a024b53535009181c'),
                    unhexlify('686974207468652062756c6c277320657965')) \
        == unhexlify('746865206b696420646f6e277420706c6179')

# challenge 3
cipher = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
print(brute_xor(unhexlify(cipher), c_max=1, charset=printable.encode()))

# challenge 4
import requests
content = requests.get('https://cryptopals.com/static/challenge-data/4.txt').text
print(max([brute_xor(unhexlify(line), c_max=1, charset=printable.encode()) for line in content.split('\n')]))

# challenge 5
plain = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
target = b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
assert stream_xor(plain, b"ICE") == unhexlify(target)

# challenge 6
assert hamming(b'this is a test', b'wokka wokka!!!') == 37
content = requests.get('https://cryptopals.com/static/challenge-data/6.txt').text
content = b64decode(content)
print(break_repeated_xor(content))

# challenge 7
content = requests.get('https://cryptopals.com/static/challenge-data/7.txt').text
cryptor = AES.new(b'YELLOW SUBMARINE', AES.MODE_ECB)
print(cryptor.decrypt(b64decode(content)))

decrypted = b''
for line in content.split('\n'):
    decrypted += cryptor.decrypt(b64decode(content))
print(decrypted)

# challenge 8
content = requests.get('https://cryptopals.com/static/challenge-data/8.txt').text.strip().split('\n')
max_freq, max_cipher = None, None

from collections import Counter
for line in content:
    line = unhexlify(line)
    blocks = []
    for i in range(0, len(line), 16):
        blocks.append(line[i : i + 16])
    max_ = max(Counter(blocks).values())
    if max_freq is None or max_freq < max_:
        max_freq, max_cipher = max_, line
print(max_freq, max_cipher)

print(AES.new(b'YELLOW SUBMARINE'.lower(), AES.MODE_ECB).decrypt(max_cipher))
