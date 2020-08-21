<sup>Đây là một bài trong series [Cùng giải Cryptopals!](https://viblo.asia/s/cung-giai-cryptopals-68Z00nw9ZkG).<br>Các bạn nên tự làm hoặc vừa đọc vừa làm thay vì đọc lời giải trực tiếp.</sup>

Do phần này khá ngắn nên mình sẽ viết toàn bộ phần 1 trong 1 bài Viblo. Những bài sau lằng nhằng hơn sẽ có thể sẽ được mình chia nhỏ ra thành nhiều bài viết.

***
**<div align="center">Không chần chừ gì nữa, hãy bắt đầu nào!</div>**
***

# [Challenge 1: Convert hex to base64](https://cryptopals.com/sets/1/challenges/1)
Khá đơn giản với Python: chúng ta cần đổi từ hex sang plaintext trước:
```python
from binascii import unhexlify
# input: hex_
str_ = unhexlify(hex_)
```
Cần chú ý rằng biến `str_` ở đây là bytestring chứ không phải UTF-8. Ngoài ra, để hiểu thêm mục này các bạn có thể implement lại hàm unhexlify lại:
```python
def unhexlify(hex_: str) -> bytes:
    # strip 0x at the beginning if needed
    hex_ = hex_.lstrip('0x')
    # zero-padding
    if len(hex_) % 2: hex_ = '0' + hex_
    bytelist = []
    for i in range(0, len(hex_), 2):
        bytelist.append(int(hex_[i * 2 : i * 2 + 2], 16))
    return bytes(bytelist)
```
Về cơ bản, mỗi số (1 byte/2 hexdigits) trong hexstring đó sẽ tương ứng với một chữ cái. Chú ý: hàm này sẽ chỉ nhận đầu vào là string thường, trong khi `binascii.unhexlify` nhận của string thường lẫn bytestring.

Rồi đổi từ string qua base64: mục này lằng nhằng nên mình sẽ không implement tay đâu 😅
```python
from base64 import b64encode
b64_ = b64encode(str_)
```

Ghép tất cả lại với nhau, ta có:
```python
from binascii import unhexlify
from base64 import b64encode
def hex2b64(hex_: hex) -> bytes:
    return b64encode(unhexlify(hex_))
```

Các bạn hãy tự test tay ví dụ trên trang đó để check nhé! 

**Easter egg:** By the way, test string đó sau khi decode từ hex về string sẽ ra
```
b"I'm killing your brain like a poisonous mushroom"
```
là một câu trong bài hát [Ice Ice Baby của Vanilla Ice](https://www.youtube.com/watch?v=rog8ou-ZepE). Trong set này sẽ có rất nhiều references như vậy, nên hãy để ý :D

# [Challenge 2: Fixed XOR](https://cryptopals.com/sets/1/challenges/2)
Cho 2 chuỗi hex có độ dài bằng nhau, cần XOR chúng ra chuỗi hex kết quả. Thứ tự các bước sẽ như sau:
- Việc đầu tiên là đổi cả 2 chuỗi hex ra các bytes để chúng ta có thể XOR:
```python
from binascii import unhexlify
# input: hex1, hex2
hex1 = unhexlify(hex1)
hex2 = unhexlify(hex2)
```
- Sau đó, chúng ta XOR từng cặp byte:
```python
bytelist = []
for i in range(len(hex1)):
    bytelist.append(hex1[i] ^ hex2[i])
bytelist = bytes(bytelist)
```
- Và cuối cùng, chúng ta chuyển hết lại về dạng hex:
```python
from binascii import hexlify
xored = hexlify(bytelist)
```
Ghép hết tất cả vào kèm với viết tắt bằng cách xử lý kiểu functional, ta có:
```python
from binascii import hexlify, unhexlify
def hex_xor(hex1: hex, hex2: hex) -> hex:
    return hexlify(bytes(x ^ y for x, y in zip(unhexlify(hex1), unhexlify(hex2))))
```
Bạn có thể sử dụng `map` thay vì list comprehension, nhưng code sẽ bị dài ra chút. Hãy thử xem!

**Easter egg:** hexstring thứ 2 sẽ decode ra
```
b"hit the bull's eye"
```
và kết quả cuối cùng decode ra
```
b"the kid don't play"
```
Đây là một câu khác trong lời bài hát Ice Ice Baby; tuy nhiên có hơi sai một chút, lời đúng của bài hát là
> You better hit bull's eye, the kid don't play

Sự sai lệch này chắc là vì tác giả phải sửa sao cho 2 chuỗi này có cùng độ dài :D

# [Challenge 3: Single-byte XOR cipher](https://cryptopals.com/sets/1/challenges/3)
Việc đầu tiên là chúng ta cần phải tạo ra một stream XOR trước :D Sau đó, chúng ta có thể bruteforce xem key là gì sau.  Hơi nhảy trước ánh đèn ô tô tí, nhưng về cơ bản thì đây là stream cipher, khi key của bạn được lặp lại liên tục cho đến khi đủ độ dài của string cần mã hoá. Vì vậy, chúng ta chỉ cần sử dụng fixed XOR với key đã được lặp lại:
```python
from binascii import hexlify, unhexlify
from itertools import cycle
def hex_xor(hex1: hex, hex2: hex) -> hex:
    # will repeat hex2 (the key) if needed.
    return hexlify(bytes(x ^ y for x, y in zip(unhexlify(hex1), cycle(unhexlify(hex2)))))
```

Thậm chí, các bạn có thể để ý rằng thực ra fixed XOR cũng chỉ là một phiên bản đặc biệt của streaming XOR! Nên, từ bây giờ chúng ta có thể tạm bỏ qua nó và chỉ dùng streaming XOR thôi.

Sau đó, chúng ta sẽ nghĩ ngay đến việc thử tất cả các key xem có bản đã giải mã nào mà không có ký tự lạ nào là được. Code thì dễ thôi:

```python
from string import printable
# input: cipher
def is_printable(hex_: hex) -> bool:
    return len(set(unhexlify(s)) - set(printable.encode())) == 0

for key in printable:
    decrypted = hex_xor(cipher, hexlify(key.encode()))
    if is_printable(decrypted):
        print(key, unhexlify(decrypted))
```

Tuy nhiên, phương pháp trẻ con đó cho chúng ta nhiều hơn 1 đáp án! Vì vậy, chúng ta sẽ phải sử dụng một kỹ thuật xịn hơn, đó là **frequency analysis**. Về cơ bản, ta sẽ thử tất cả các key có thể (thử với tất cả các chữ cái, như hint của bài cho biết). Sau đó, với mỗi một chuỗi đưa ra, chúng ta cần check xem tần số các chữ cái có giống với tiếng Anh không. Ngày xưa lúc mình còn bé, mình chỉ check xem top 6 chữ cái hay xuất hiện nhất có phải là `etaoin` không. Tuy nhiên, bây giờ đã là dân giang hồ AI, chúng ta phải sử dụng một metrics cụ thể: với 2 phân bố, chúng ta có thể tìm ra được độ khác nhau của chúng. Một trong các lựa chọn metrics đó là [log likelihood](https://en.wikipedia.org/wiki/Cross_entropy#Relation_to_log-likelihood):

$$
\mathcal{L}_\mathbf{p}(\mathbf{p'})=\sum_c\mathbf{p}(c)\log\mathbf{p'}(c)
$$

với $c$ là các chữ cái trong bảng chữ cái.

```python
# from http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
ENGLISH_FREQ = {
    'A' :  8.55,    'K' :  0.81,    'U' :  2.68,
    'B' :  1.60,    'L' :  4.21,    'V' :  1.06,
    'C' :  3.16,    'M' :  2.53,    'W' :  1.83,
    'D' :  3.87,    'N' :  7.17,    'X' :  0.19,
    'E' : 12.10,    'O' :  7.47,    'Y' :  1.72,
    'F' :  2.18,    'P' :  2.07,    'Z' :  0.11,
    'G' :  2.09,    'Q' :  0.10,                 
    'H' :  4.96,    'R' :  6.33,                 
    'I' :  7.33,    'S' :  6.73,                 
    'J' :  0.22,    'T' :  8.94,    
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
```
Nếu bạn để ý thì hàm `get_score` có một đầu vào lại là `replace`: Cụ thể là khi `replace=True`, decrypt candidate của chúng ta sẽ không tính các chữ cái thường xuất hiện trong đoạn văn tiếng Anh (chấm phẩy, dấu cách, v.v...), từ đó sẽ làm giảm độ dài của string và tăng probability của $\mathbf{p'}$ về gần hơn $\mathbf{p}$. Như một hệ quả, khi so sánh các chuỗi có các chữ cái trong bảng chữ cái giống nhau, thì chuỗi nào có ít các ký tự rác hơn sẽ có điểm cao hơn.

Sau đó, chúng ta so sánh các likelihood của các chuỗi đã giải mã giống với phân bố chuẩn của tiếng Anh, và lấy chuỗi nào có giá trị lớn nhất thôi. Trong code trên của mình có thêm $10^{-12}$ vào các giá trị tần số không tồn tại ($p'=0$) để tránh numerical instability, vì $\log 0 = -\infty$ sẽ ra các kết quả toang. Các bạn hãy tự viết công thức ra để tìm hiểu tại sao code mình đúng nhé (^^;)

```python
# rewrite to work with bytes instead of hex
def stream_xor(b1: bytes, b2: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(b1, cycle(b2)))

def brute_xor(cipher: bytes,
              c_min: int = 1,
              c_max: int = 4,
              charset: Iterable[bytes] = printable.encode()
             ) -> (bytes, bytes):
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
```

Nếu không sử dụng normalizing constant (với `replace` trong hàm `get_score`), dùng phương pháp này ra một kết quả khá là đáng sợ:
```
b'cOOKING\x00mc\x07S\x00LIKE\x00A\x00POUND\x00OF\x00BACON'
```
với key `x`. Tuy nhiên, với các chữ cái bị ngược case như thế này nghĩa là casing bit đã bị ngược, vậy chúng ta đổi case key (thành `X`) là sẽ ra được đáp án. Nếu chúng ta để `replace=True` thì đáp án đúng sẽ xuất hiện.

**Easter egg:** đáp án của bài này là
```
b"Cooking MC's like a pound of bacon"
```
cũng là lyrics của Ice Ice Baby.

# [Challenge 4: Detect single-character XOR](https://cryptopals.com/sets/1/challenges/4)

Với code phần 3 thì câu này lại chả quá dễ rồi.
```python
import requests
content = requests.get('https://cryptopals.com/static/challenge-data/4.txt').text
print(max([brute_xor(unhexlify(line), c_max=1) for line in content.split('\n')]))
```

**Easter egg:** Đáp án lần này cũng là lyrics (chắc không phải nhắc lại đâu nhỉ...)
```
b'Now that the party is jumping\n'
```

# [Challenge 5: Implement repeating-key XOR](https://cryptopals.com/sets/1/challenges/5)

Thực ra mình đã code cái này từ trên, vì biết trước cái này sẽ bị hỏi nên đã nhảy trước đầu ô tô :D

*Chú ý:* các block trong đề bài đều là liền nhau. Plaintext block là 2 dòng nhưng encrypt trong cùng một lần, cách nhau bởi newline (`\n`). Cipher block là 1 dòng hex, chẳng qua dài quá nên bị chia đôi thành 2.

**Easter egg:** 2 câu cần encrypt chính là lyrics
```
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
```
và key `ICE` là nickname của ca sĩ (Vanilla Ice), lý do tại sao tên bài có tên như vậy.

***
**<div align="center">Và cuộc vui giờ mới chỉ bắt đầu.</div>**
***

# [Challenge 6: Break repeating-key XOR](https://cryptopals.com/sets/1/challenges/6)

Như đã được hint, việc đầu tiên chúng ta cần làm là implement Hamming distance cho 2 string. Do không quá khó nên mình chỉ đưa ra lời giải thôi.

*Chú ý:* Hamming distance ở đây được tính theo **bit** chứ không phải **byte**! Lần đầu mình làm set này cũng bị nhầm như vậy.

```python
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

assert hamming(b'this is a test', b'wokka wokka!!!') == 37
```

Sau đó, chúng ta sử dụng Hamming distance để đoán độ dài của key. Đây là mục 1-4 của hướng dẫn câu đó.
```python
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
```

Và phần còn lại là đoán từng chữ cái một của key:
```python
    key = b''
    for i in range(_min_keysize):
        _, keychar, _ = brute_xor(cipher[i::_min_keysize], c_max=1)
        key += keychar
    
    return key, stream_xor(cipher, key)
```

Rồi chúng ta chạy và in ra đáp án thôi.
```python
import requests
content = requests.get('https://cryptopals.com/static/challenge-data/6.txt').text
content = b64decode(content)
print(break_repeated_xor(content))
```

**Easter egg:** Key của bài này là
```
b'Terminator X: Bring the noise'
```
"[Bring The Noise](https://www.youtube.com/watch?v=l_Jeyif7bB4)" là tên một bài hát của nhóm nhạc Public Enemy, trong đó [Terminator X](https://en.wikipedia.org/wiki/Terminator_X) là DJ của nhóm hip-hop đó.

Và, plaintext của bài đó là toàn bộ lyrics của bài ["Play That Funky Music" của Vanilla Ice](https://www.youtube.com/watch?v=zNJ8_Dh3Onk) — do rất dài nên mình sẽ không copy lại.

# [Challenge 7: AES in ECB mode](https://cryptopals.com/sets/1/challenges/7)

Do ECB sử dụng lại encryptor/decryptor mà không có IV (hay IV toàn null bytes, nên chúng ta có thể khởi đầu trước):

```python
import requests
content = requests.get('https://cryptopals.com/static/challenge-data/7.txt').text
cryptor = AES.new(b'YELLOW SUBMARINE', AES.MODE_ECB)
```
Mình không implement lại AES vì:
- Quá khó hiểu :( Mình kệ nó luôn như hộp đen.
- AES được coi là an toàn, có nghĩa là sẽ không có exploit nào phá được nó.

Bây giờ muốn giải dễ nhất thì dùng hàm của PyCryptodome là xong:
```python
print(cryptor.decrypt(b64decode(content)))
```

Hoặc để thử cho chắc kèo thì do ECB encrypt từng block một, chúng ta chia nhỏ file encrypted thành từng block rồi decrypt dần:
```python
decrypted = b''
for line in content.split('\n'):
    decrypted += cryptor.decrypt(b64decode(content))
print(decrypted)
```
Kết quả sẽ ra giống nhau thôi :)

**Easter egg:** Plaintext của bài này cũng là toàn bộ lyrics của bài Play That Funky Music. Ngoài ra, ngoài lý do để key dài đúng 16 chữ cái, [Yellow Submarine](https://www.youtube.com/watch?v=m2uTFF_3MaA) là tên một bài hát của The Beatles.

# [Challenge 8: Detect AES in ECB mode](https://cryptopals.com/sets/1/challenges/8)

Đề bài đã hint một cách lộ liễu rằng ECB sẽ cho ciphertext giống nhau cho các plaintext block giống nhau. Với mỗi dòng trong file đó, chúng ta chia nhỏ thành từng block 16 bytes, và xem có dòng nào có block nào lặp lại nhiều hơn 1 lần không.

```python
import requests
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
```

Nếu bạn in hết ra để nhìn sẽ thấy có đúng 1 dòng có 1 block lặp lại 4 lần, và code của chúng ta sẽ cho đúng dòng đó. Rất tiếc mình không tìm ra key và plaintext của bài này :(

***
**<div align="center">Hết rồi đó.</div>**
***