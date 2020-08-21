<sup>Đây là một bài trong series [Cùng giải Cryptopals!](https://viblo.asia/s/cung-giai-cryptopals-68Z00nw9ZkG).<br>Các bạn nên tự làm hoặc vừa đọc vừa làm thay vì đọc lời giải trực tiếp.</sup>
***
**<div align="center">Không chần chừ gì nữa, hãy bắt đầu nào!</div>**
***

# [Challenge 9: Implement PKCS#7 padding](https://cryptopals.com/sets/2/challenges/9)

Câu này đơn giản khỏi phải giải thích:
```python
def pkcs7(s: bytes, length: int) -> bytes:
    diff = length - len(s)
    assert 0 <= diff < 256
    return s + bytes([diff] * diff)

assert pkcs7(b"YELLOW SUBMARINE", 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04"
```

**Easter egg:** Như đã nói ở phần trước, [Yellow Submarine](https://www.youtube.com/watch?v=m2uTFF_3MaA) là tên một bài hát của The Beatles.

# [Challenge 10: Implement CBC mode](https://cryptopals.com/sets/2/challenges/10)

Với giản đồ này thì việc code CBC chắc cũng vô cùng đơn giản thôi nhỉ?

![](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/600px-CBC_decryption.svg.png)

```python
def AES_decrypt(key: bytes, cipher: bytes, mode: str) -> bytes:
    cryptor = AES.new(key, AES.MODE_ECB)
    last_block = b'\x00' * 16
    decrypted = b''
    for i in range(0, len(content), 16):
        decrypted += stream_xor(cryptor.decrypt(cipher[i : i + 16]), last_block)
        if mode == 'cbc':
            last_block = content[i : i + 16]
    return decrypted
```

Rồi giải mã file của họ thôi:
```python
content = b64decode(requests.get('https://cryptopals.com/static/challenge-data/10.txt').text)
print(AES_decrypt(b'YELLOW SUBMARINE', content, 'cbc'))
```

**Easter egg:** Plaintext của bài đó là toàn bộ lyrics của bài ["Play That Funky Music" của Vanilla Ice](https://www.youtube.com/watch?v=zNJ8_Dh3Onk).

# [Challenge 11: An ECB/CBC detection oracle](https://cryptopals.com/sets/2/challenges/11)
Giản đồ của mã hoá CBC là như sau:

![](https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/600px-CBC_encryption.svg.png)

Tương tự như phần 10, ta implement AES encryptor:
```python
def AES_encrypt(key: bytes, plain: bytes, mode: str) -> bytes:
    cryptor = AES.new(key, AES.MODE_ECB)
    last_block = b'\x00' * 16
    encrypted = b''
    for i in range(0, len(plain), 16):
        last_block = cryptor.encrypt(stream_xor(plain[i : i + 16], last_block))
        encrypted += last_block
        if mode == 'ecb':
            last_block = b'\x00' * 16
    return encrypted
```

Rồi tạo encryption oracle như đề bài:
```python
def generate_key(length: int = 16) -> bytes:
    # NOT cryptographically secure!
    return bytes([randint(0, 255) for _ in range(length)])

def encryption_oracle(s: bytes) -> bytes:
    mode = 'ecb' if randint(0, 1) == 0 else 'cbc'
    s = generate_key(randint(5, 10)) + s + generate_key(randint(5, 10))
    s = pkcs7(s, len(s) + 16 - (len(s) % 16))
    return AES_encrypt(generate_key(), s, mode), mode
```
Trong đó, chúng ta return `mode` để so sánh với các dự đoán sau này. Do đây là oracle, chúng ta được chọn plaintext để encrypt; và vì với ECB thì các block plaintext giống nhau sẽ có cipher giống nhau, chúng ta chọn plaintext sao cho block 2 và block 3 giống nhau là được: chọn plaintext là 48 chữ cái `'a'` (3 blocks) là thừa đủ.

```python
for _ in range(100):
    cipher, mode = encryption_oracle(b'a'* (16 * 3))
    if cipher[16:32] == cipher[32:48]:
        if mode != 'ecb':
            print('wrong')
    else:
        if mode != 'cbc':
            print('wrong')
```
Chạy từng đó lần và sẽ không ra sai phát nào đâu :D

# [Challenge 12: Byte-at-a-time ECB decryption (Simple)](https://cryptopals.com/sets/2/challenges/12)

Đầu tiên chúng ta sẽ tạo một encryption oracle trước:
```python
random_key = generate_key()
unknown_string = b64decode(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
def encryption_oracle(s: bytes) -> bytes:
    s += unknown_string
    s = pkcs7(s, len(s) + 16 - (len(s) % 16))
    return AES_encrypt(random_key, s, 'ecb')
```

- *Bước 1:* thử xem blocksize là bao nhiêu:
```python
blocksize = 0
firstbreak = None
last_length = len(encryption_oracle(b'A' * blocksize))
while True:
    blocksize += 1
    new_length = len(encryption_oracle(b'A' * blocksize))
    if new_length != last_length:
        if firstbreak is None:
            firstbreak = blocksize
            last_length = new_length
        else:
            # length of each encrypted block
            block_length = new_length - last_length
            # number of blocks
            block_count = len(encryption_oracle(b'')) // block_length
            print(block_length, block_count) # 16 9
            # length of each encryption block
            blocksize = blocksize - firstbreak
            print(blocksize) # 16
            break
```
Từ đó ta biết được mã hóa mỗi 16 bytes, và có tổng cộng 9 blocks. Từ đó, ta sẽ padding đủ 9 blocks: `'A' * (16 * 9)`.

- *Bước 2:* detect xem có đang dùng ECB — các bạn tự sửa code của challenge trước nhé mình lười lắm.

- *Bước 3:* Làm theo đúng hướng dẫn trong bài:
```python
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
    for _ in range(length):
        payload = b'A' * (length - len(found) - 1)
        truth = oracle(payload)[:block_count * cipher_length]
        for b in range(256):
            if oracle(payload + bytes(found + [b])).startswith(truth):
                found.append(b)
                break
    return bytes(found)

print(brute_ecb_prepadding(encryption_oracle, block_count, blocksize, block_length))
```

**Easter egg:** Plaintext của bài này:
> Rollin' in my 5.0<br>
> With my rag-top down so my hair can blow<br>
> The girlies on standby waving just to say hi<br>
> Did you stop? No, I just drove by

là lyrics của bài hát [Rollin In My 5.0 của Vanilla Ice](https://www.youtube.com/watch?v=gMbxOUgPDsI).

# [Challenge 13: ECB cut-and-paste](https://cryptopals.com/sets/2/challenges/13)

Chúng ta bắt đầu bằng việc implement hàm chuyển đổi từ cookie string sang `dict`:
```python
def cookie2dict(s: str) -> dict:
    return dict(map(lambda x: x.split('='), s.strip('&').split('&')))

assert cookie2dict('foo=bar&baz=qux&zap=zazzle') == {
    'foo': 'bar',
    'baz': 'qux',
    'zap': 'zazzle'
}
```

Và một hàm tương tự cho chiều ngược lại:
```python
def dict2cookie(d: dict) -> str:
    # assume all k-v are strings
    return '&'.join(map('='.join, d.items()))

assert dict2cookie({
    'foo': 'bar',
    'baz': 'qux',
    'zap': 'zazzle',
}) == 'foo=bar&baz=qux&zap=zazzle'
```

Tiếp đến là hàm `profile_for`:
```python
def profile_for(email: str):
    return dict2cookie({
        'email': email.replace('&', '').replace('=', ''),
        'uid': str(10),
        'role': 'user'
    })

assert profile_for("foo@bar.com") == 'email=foo@bar.com&uid=10&role=user'
```

Trước khi tới phần tiếp theo, chúng ta cần implement hàm bỏ PKCS#7 padding sau decryption:
```python
def pkcs7_unpad(s: bytes) -> bytes:
    return s[:-s[-1]]
```

Rồi tạo 2 function, encryptor cho attacker và decryptor cho vui:
```python
random_key = generate_key()
# for the attacker
def encrypt_profile(email: str) -> bytes:
    s = profile_for(email).encode()
    s = pkcs7(s, len(s) + 16 - (len(s) % 16))
    return AES_encrypt(random_key, s, 'ecb')

def decrypt_profile(s: bytes) -> dict:
    return cookie2dict(pkcs7_unpad(AES_decrypt(random_key, s, 'ecb')).decode())
```

Và cách xử lý để tạo một cookie admin như sau:
- Chúng ta chọn 1 email có độ dài sao cho đến ngay trước `role` chia hết cho 16 (chiếm vừa hết các block): ở đây mình chọn `bad@email.com` sẽ tạo ra cookie có đoạn đầu là 
```
email=bad@email.com&uid=10&role=
```
có độ dài là 32, đúng như mong muốn.
- Chúng ta cần thay thế block cuối
```
user\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c
```
thành
```
admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
```
Do chúng ta có oracle, nên có thể lấy được block đó dễ như chơi. Chỉ cần tạo email sao cho chuỗi trên chiếm full một block là chúng ta có thể lấy được cipher block đó. Ở đây mình chọn payload là
```python
'A' * 10 + 'admin' + '\x0b' * 11
```
sẽ tạo ra cookie có 32 bytes đầu là
```
email=AAAAAAAAAA
admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
```
Vậy chúng ta chỉ cần lấy block số 2 trong cipher text nhận về là được:

```python
poison = encrypt_profile('A' * 10 + 'admin' + '\x0b' * 11)
user = encrypt_profile('bad@email.com')
crafted = user[:-16] + poison[16:32]
print(decrypt_profile(crafted))
```

Output ra đúng những gì đã sắp đặt:
```
{'email': 'bad@email.com', 'uid': '10', 'role': 'admin'}
```

# [Challenge 14: Byte-at-a-time ECB decryption (Harder)](https://cryptopals.com/sets/2/challenges/14)

Bài này chỉ khác bài challenge 12 là có prefix một chuỗi bừa trước oracle. Chúng ta tạo oracle trước:

```python
random_key = generate_key()
random_length = randint(0, 100)
random_prefix = generate_key(random_length)
unknown_string = b64decode(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
def encryption_oracle(s: bytes) -> bytes:
    s = random_prefix + s + unknown_string
    s = pkcs7_pad(s)
    return AES_encrypt(random_key, s, 'ecb')
```

Vậy bài này chỉ cần làm thêm 2 bước:
- Tìm độ dài của prefix: chúng ta cứ tăng dần chuỗi cho đến khi block bị thay đổi dừng thay đổi: ví dụ như prefix là `STIMULUS`, thì khi ta thêm dần các chữ `A` sẽ có block đầu tiên bị thay đổi liên tục cho đến khi được fill đầy block thành `STIMULUSAAAAAA`: lúc đó block này sẽ dừng thay đổi, và block tiếp theo bị thay đổi.
```python
previous = encryption_oracle(b'')
idx = None
for i in range(1, 17):
    current = encryption_oracle(b'A' * i)
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
```
- Tạo oracle surrogate cầu nối bài này với code cũ: trước payload của chúng ta sẽ nhét thêm rác vào để cho random prefix đủ trọn block, rồi xoá nó đi mà làm lơ.
```python
def surrogate_oracle(s: bytes) -> bytes:
    block_count = prefix_length // 16 + 1
    leftover = prefix_length % 16
    return encryption_oracle(b'A' * (16 - leftover) + s)[16 * block_count:]
```

Rồi giải như bài 12 thôi!
```python
print(brute_ecb_prepadding(surrogate_oracle, 9, 16))
```

# [Challenge 15: PKCS#7 padding validation](https://cryptopals.com/sets/2/challenges/15)

Chúng ta chỉ cần sửa hàm `pkcs7_unpad` và raise exception nếu padding không hợp lệ.

```python
def pkcs7_unpad(s: bytes) -> bytes:
    assert s[-s[-1]:] == s[-1:] * s[-1]
    return s[:-s[-1]]

pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04")
pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05") # AssertionError
```

**Easter egg:** Plaintext lần này lại có nhắc tới Ice Ice Baby.

# [Challenge 16: CBC bitflipping attacks](https://cryptopals.com/sets/2/challenges/16)

Đầu tiên, chúng ta cần implement 2 function cần thiết cho bài này, tương tự như challenge 13:

```python
random_key = generate_key()
def encrypt_data(s: str) -> bytes:
    s = r"comment1=cooking%20MCs;userdata=" + s.replace('=', '').replace(';', '') + r";comment2=%20like%20a%20pound%20of%20bacon"
    s = pkcs7_pad(s.encode())
    return AES_encrypt(random_key, s, 'cbc')

def is_admin(s: bytes) -> bool:
    return b'admin=true' in pkcs7_unpad(AES_decrypt(random_key, s, 'cbc')).split(b';')
```

Đây là giản đồ CBC decryption như ở trên để các bạn có thể dễ nhìn hơn:

![](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/600px-CBC_decryption.svg.png)

Với trường data định bắn vào thì đây là các plaintext sau khi chia block:
```
comment1=cooking
%20MCs;userdata=
kwkt;admin=true;
;comment2=%20lik
e%20a%20pound%20
of%20bacon
```

Để ý giản đồ trên và tập trung vào block 2 và 3. Chọn payload vào đó là 16 chứ `A`, hiện tại chúng ta có:
```
cipher[2] XOR decrypt(cipher[3]) = 'AAAAAAAAAAAAAAAA'
```

Giờ để plaintext của block 3 thành `kwkt;admin=true;`, chúng ta chỉ cần sửa ciphertext của block 2 sao cho XOR ra được chuỗi chúng ta muốn:
```
cipher[2] = cipher[2] XOR 'AAAAAAAAAAAAAAAA' XOR 'kwkt;admin=true;'
```
Thay thế vào công thức trên bạn sẽ thấy vế phải ra đúng payload cần của chúng ta. Cụ thể hơn, decrypt ciphertext đã sửa đó sẽ ra
```
comment1=cooking
[ 16 bytes rác ]
kwkt;admin=true;
;comment2=%20lik
e%20a%20pound%20
of%20bacon
```

Thế là thành công rồi. Giờ thì viết tí code là ra thôi:
```python
cipher = encrypt_data('A' * 16)
bitflip = stream_xor(cipher[16:32],
          stream_xor(b'A' * 16, b"kwkt;admin=true;"))
payload = cipher[:16] + bitflip + cipher[32:]
print(is_admin(payload)) # True
```

**Easter egg:** Trường `comment1` và `comment2` ghép lại ra
> Cooking MCs like a pound of bacon

là lyrics của Ice Ice Baby.

***
**<div align="center">Hết rồi đó.</div>**
***