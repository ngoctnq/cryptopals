<sup>Đây là một bài trong series [Cùng giải Cryptopals!](https://viblo.asia/s/cung-giai-cryptopals-68Z00nw9ZkG).<br>Các bạn nên tự làm hoặc vừa đọc vừa làm thay vì đọc lời giải trực tiếp.</sup>
***
**<div align="center">Không chần chừ gì nữa, hãy bắt đầu nào!</div>**
***

# [Challenge 17: The CBC padding oracle](https://cryptopals.com/sets/3/challenges/17)

Việc đầu tiên phải làm là implement các hàm cần thiết cho bài tập:
```python
strings = [
    'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    ...
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
```
Như đã hint trong bài, chúng ta có thể tấn công padding oracle với *bất cứ* block nào, không nhất thiết phải là block cuối. Cứ mỗi lần đụng vào CBC là mình sẽ trình lại giản đồ này vì thực sự nó rất dễ hình dung:

![](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/600px-CBC_decryption.svg.png)

Trong mỗi block thì sau khi AES decrypt, XOR các mục sau:

```
decrypted       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
last cipher     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
-----------------------------------------------
plaintext       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
```
Và chúng ta muốn sửa cipher trước (hay còn gọi là IV) sao cho plaintext đã sửa ra được một valid padding (nếu việc sửa cipher còn lạ lẫm, hãy ngẫm lại challenge 16 của set 2). Ví dụ cho chữ cái đầu tiên, chúng ta sẽ sửa byte cuối cùng của IV sao cho byte cuối cùng của plaintext (đã sửa) là `\x01`. Giả sử byte cuối của IV là `b`, và byte cuối đã sửa để có valid padding là `b_`: chúng ta có
```
plaintext[-1] = decrypted[-1] XOR b
```
và
```
'\x01' = decrypted[-1] XOR b_
```
nên sẽ lấy được byte cuối cùng của plaintext thật bằng:
```
plaintext[-1] = '\x01' XOR b XOR b_
```

*Chú ý:* Sẽ xảy ra một khả năng nếu bạn đen như sau: nếu byte áp chót thật là `\x02`, thì sau khi bạn sửa IV thì `\x01` hay `\x02` đều được coi là byte cuối cho valid padding. Vì vậy, do chúng ta chỉ muốn `\x01`, hay thay đổi byte áp chót của IV, và chỉ chấp nhận nếu plaintext vẫn có valid padding.

Sau đó, chúng ta sẽ sửa byte áp chót của IV (nhớ sửa lại byte cuối IV sao cho plaintext thành `\x02` thay vì `\x01`), cứ thế dần cho đến khi giải mã được toàn bộ plaintext.

Ghép hết tất cả lại, chúng ta có:
```python
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
```

Và để giải mã tất cả thì chúng ta gọi hàm giải mã từng block dần dần từ đầu đến cuối:
```python
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
```

Và chạy hàm giải mã:
```python
cipher, iv = random_encrypt()
print(pkcs7_unpad(padding_oracle_attack(cipher, check_padding, iv)))
```

**Easter egg:** Như thông lệ, các dòng base64 kìa là lời bài hát của Ice Ice Baby.
> Now that the party is jumping<br>
> With the bass kicked in and the Vega's are pumpin'<br>
> Quick to the point, to the point, no faking<br>
> Cooking MC's like a pound of bacon<br>
> Burning 'em, if you ain't quick and nimble<br>
> I go crazy when I hear a cymbal<br>
> And a high hat with a souped up tempo<br>
> I'm on a roll, it's time to go solo<br>
> Rollin' in my five point oh<br>
> with my rag-top down so my hair can blow<br>

# [Challenge 18: Implement CTR, the stream cipher mode](https://cryptopals.com/sets/3/challenges/18)

Ý chính của bài này là chúng ta phải tạo được keystream để XOR dần với plaintext/ciphertext.
```python
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
```

Và chạy.
```python
encrypt_ctr(
    b"YELLOW SUBMARINE",
    b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
)
```

**Easter egg:** Đáp án của bài này là
> Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby

là câu đầu tiên trong bài Ice Ice Baby.

# [Challenge 19: Break fixed-nonce CTR mode using substitutions](https://cryptopals.com/sets/3/challenges/19)

Đầu tiên, chúng ta implement code sinh ra bài toán để giải:
```python
strings = [...]
seed('no random')
random_key = generate_key()
encrypted = [encrypt_ctr(random_key, b64decode(s)) \
    for s in strings]
```

Giờ do keystream được dùng đi dùng lại nhiều lần, về cơ bản là đây giống như tìm phá Repeated XOR (check lại Set 1 Challenge 6 nếu bạn có lỡ quên). Vì thế, làm tương tự với code có sẵn, chúng ta tạm giải ra đáp án sơ bộ:

```python
stream_len = max(map(len, encrypted))
# we'll update this
keystream = [0] * stream_len
for i in range(stream_len):
    cipher = bytes([x[i] for x in encrypted if len(x) > i])
    # we'll just guess these later
    if len(cipher) < 4:
        continue
    _, key, _ = brute_xor(cipher, c_max=1)
    keystream[i] = key[0]

keystream = bytes(keystream)
for cipher in encrypted:
    print(stream_xor(cipher, keystream))
```

Và đầu ra chúng ta có (trích xuất vài dòng đầu):
```
b'N have met them at close nf\x01day'
b'Doming with vivid faces'
b'Arom counter or desk amonf Frey'
b'Bighteenth-century houses/'
...
```

Như đã hint thì chúng ta sẽ phải fix tay nhiều chỗ. Có thể đoán được rằng đúng ra chữ cái đầu tiên của dòng đầu tiên phải là `I` thay vì `N`; vì vậy chúng ta sẽ sửa tay byte đầu tiên của key bằng cách XOR qua cả 2 chữ cái đó. Cứ như vậy ta sẽ ra được toàn bộ các decrypted strings.

```python
keystream[0] ^= ord('N') ^ ord('I')
keystream[25] ^= ord('f') ^ ord('g')
keystream[27] ^= 0x01 ^ ord(' ')
keystream[31] ^= ord('!') ^ ord(' ')
keystream[32] ^= ord('I') ^ ord('d')
keystream[34] ^= ord('Q') ^ ord('a')
keystream[35] ^= ord('e') ^ ord('d')
keystream[36] ^= ord('Y') ^ ord('n')
keystream[37] ^= 0x0c ^ ord(',')
```

**Easter egg:** chỗ base64 decode ra bài thơ "Easter, 1916" của nhà thơ nổi tiếng người Ai-len William Butler Yeats.

# [Challenge 20: Break fixed-nonce CTR statistically](https://cryptopals.com/sets/3/challenges/20)

Hình như cách làm challenge 19 của mình mới là lời giải bài 20 😰 Chỉ cần thay đúng dòng đầu là được:
```python
strings = requests.get('https://cryptopals.com/static/challenge-data/20.txt').text.strip().split('\n')
```

**Easter egg:** Plaintext của bài này là lời bài hát [Lyrics of Fury của Eric B. & Rakim](https://www.youtube.com/watch?v=GFOeJOtq_xc).

# [Challenge 21: Implement the MT19937 Mersenne Twister RNG](https://cryptopals.com/sets/3/challenges/21)

Bài này chỉ cần reimplement lại Mersenne Twister RNG theo [pseudocode trên Wikipedia](https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode). Implementation của mình như sau:

```python
# reimplementation of MT19937 based on Wiki pseudocode
w, n, m, r = 32, 624, 397, 31
a = 0x9908B0DF
u = 11
s, b = 7, 0x9D2C5680
t, c = 15, 0xEFC60000
l = 18
f = 1812433253

# Create a length n array to store the state of the generator
lower_mask = 0x7fffffff
upper_mask = 0x80000000


def seed_mt(seed: int):
    # Initialize the generator from a seed
    states = [0] * n
    states[0] = seed
    for i in range(1, n): # loop over each element
        states[i] = (f * (states[i - 1] ^ (states[i - 1] >> (w - 2))) + i) & ((1 << w) - 1)

    global generator
    generator = create_generator(states)


def twist(states):
    # Generate the next n values from the series x_i 
    for i in range(n):
        x = (states[i] & upper_mask) + (states[(i + 1) % n] & lower_mask)
        xA = x >> 1
        if x % 2 != 0:
            # lowest bit of x is 1
            xA ^= a
        states[i] = states[(i + m) % n] ^ xA


def create_generator(states):
    # Extract a tempered value based on MT[index]
    # calling twist() every n numbers
    i = 0
    while True:
        if i == 0: twist(states)

        y = states[i]
        y ^= (y >> u)
        y ^= ((y << s) & b)
        y ^= ((y << t) & c)
        y ^= (y >> l)

        i = (i + 1) % n

        yield y & ((1 << w) - 1)


# default seed
seed_mt(5489)
def get_random_number():
    return next(generator)
```

# [Challenge 22: Crack an MT19937 seed](https://cryptopals.com/sets/3/challenges/22)

Để crack seed thì mình chỉ nghĩ đến việc bruteforce nó thôi. Bắt đầu bằng code để ra đề (với code bài trên mình để trong file `mersenne_twister.py`):
```python
from mersenne_twister import seed_mt, get_random_number
from time import time

def routine():
    seed_val = int(time()) + randint(40, 1000)
    seed_mt(seed_val)
    return get_random_number(), seed_val
```

Để crack được seed thì chúng ta chỉ cần bruteforce thời gian:

```python
current_time = int(time())
random_number, seed_val = routine()

# create some slack on max rand to make up for code execution time
for i in range(2000):
    new_seed = current_time + i
    seed_mt(new_seed)
    if get_random_number() == random_number:
        break

assert new_seed == seed_val
```

# [Challenge 23: Clone an MT19937 RNG from its output](https://cryptopals.com/sets/3/challenges/23)
Hàm tempering để rải đều bit làm tăng entropy của MT là phần sau trong code:
```python
y ^= (y >> u)
y ^= ((y << s) & b)
y ^= ((y << t) & c)
y ^= (y >> l)
```

Trong đây có 2 hàm cầm phải đảo ngược:
- `y = y ^ (y >> u)`: chúng ta có thể vẽ ra quá trình XOR như sau:
```
y       0 1 2 3 4 ? ? ? ? ? ? ? ? ? ? ?
y >> u  <-- u --> 0 1 2 3 4 ? ? ? ? ? ?
---------------------------------------
result  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
```
Như vậy, ban đầu chúng ta sẽ có được $u$ bit gốc của $y$ ($u$ bit cao nhất; nếu $u$ lớn hơn số bit của $y$ thì $y$ chính là giá trị gốc). Giờ ta XOR kết quả cuối với những bit đã lấy lại được của $y$ thì ta sẽ biết thêm được $u$ bit nữa — làm vậy $\lceil\log_2\frac{\text{number of bits in } y}{u}\rceil$ lần sẽ ra được giá trị gốc.

```python
def undo_xor_shift(y: int, l: int) -> int:
    # reverse y ^= (y >> l)
    original = y
    while True:
        candidate = y ^ (y >> l)
        if candidate == original:
            return y
        else:
            y = candidate
```

- `y = y ^ ((y << s) & b)`: câu này khá là khó tưởng tượng. Chúng ta cũng có thể vẽ ra quá trình:
```
                        <-- u -->
y       <-- u --> ? ? ? ? ? ? ? ?
y << u  ? ? ? ? ? ? ? ? 0 0 0 0 0
b             0 1 2 3 4 5 6 7 8 9
---------------------------------
result  0 1 2 3 4 5 6 7 8 9 0 1 2
```
Do chúng ta biết được $u$ bit cuối cùng của `y << u` là 0, ta có thể lấy được $u$ bit cuối cùng của $y$ bằng cách tương tự phần trên. Cứ mỗi bước như vậy lại cho chúng ta $u$ bit cho đến khi có được toàn bộ $y$. Code của mình như sau:

```python
def undo_xor_shift_and(y: int, s: int, b: int) -> int:
    # reverse y ^= ((y << s) & b)
    original = y
    y = 0
    while True:
        y = (original ^ ((y << s) & b)) & ((1 << w) - 1)
        if y ^ ((y << t) & c) == original:
            return y
```
*Chú ý:* với implementation này, mỗi lần ra một candidate cho $y$ cần giới hạn lại số bit của $y$ (trong trường hợp này $w=32$). Nếu không, mỗi lần candidate của $y$ sẽ dài thêm $s$ bit.

*Chú ý 2:* với các bitshift gần ($s$, $t$ nhỏ), có thể 1 iteration không cần loop đã ra đáp án rồi. Tuy nhiên, đừng vì thế mà nghĩ rằng thuật toán này có thể ra kết quả sau đúng 1 phép toán! Tuy nhiên, nếu tồn tại thuật toán khác như vậy, hay comment cho mình ở dưới — mình rất tò mò muốn được biết.

Từ đó, ta có thể implement hàm `untemper`:
```python
def untemper(y: int) -> int:
    y = undo_xor_shift(y, l)
    y = undo_xor_shift_and(y, t, c)
    y = undo_xor_shift_and(y, s, b)
    y = undo_xor_shift(y, u)
    return y
```
Untemper đủ 624 giá trị, fill đầy bảng state, và `twist()`, chúng ta sẽ sinh ra lại được generator cũ:
```python
from time import time
from mersenne_twister import seed_mt, get_random_number, untemper, twist, create_generator

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
```

Việc sử dụng secure cryptographic hash sẽ chống lại được attack này, vì hàm hash khó reverse. Đồng thời, do tính chất không trùng, nếu phân bố của tempered output rải đều (uniform), và chúng ta chọn hàm hash có range và domain giống nhau (ở đây là 32-bit), thì kết quả sau hàm hash cũng sẽ phân bố đều. Điều này ám chỉ rằng output sau hash giống với một chuỗi ngẫu nhiên, thoả mãn tính chất của một keystream. Ngoài ra, nếu không sử dụng cryptographic hash, chúng ta có thể tạo thêm một (AES) encryptor với một mật mã khác, và mã hoá tempered output (thay vì sử dụng hàm băm). Ý tưởng này sẽ khá là giống với CTR mode: mã hoá các meaningful state sẽ cho ta một keystream như mong muốn.

# [Challenge 24: Create the MT19937 stream cipher and break it](https://cryptopals.com/sets/3/challenges/24)
Bài này là rehash lại của các concept có trước:
- Với seed chỉ có 16-bit, bruteforce 65536 trường hợp là dễ.
- Nếu muốn break seed theo phương pháp của challenge 23, ta cần có đủ 624 states của generator, tương ứng với $624  \times 32 / 8 = 2496$ bytes. Vậy chỉ cần padding của chúng ta dài từng đó, rồi XOR ra keystream thì sẽ dùng phương pháp trên được.
- Phần password reset token làm tương tự như challenge 22.
Và do mình lười nên mình sẽ không làm đâu :)

***
**<div align="center">Hết rồi đó.</div>**
***