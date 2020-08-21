<sup>Đây là một bài trong series [Cùng giải Cryptopals!](https://viblo.asia/s/cung-giai-cryptopals-68Z00nw9ZkG).<br>Các bạn nên tự làm hoặc vừa đọc vừa làm thay vì đọc lời giải trực tiếp.</sup>
***
**<div align="center">Không chần chừ gì nữa, hãy bắt đầu nào!</div>**
***

# [Challenge 25: Break "random access read/write" AES CTR](https://cryptopals.com/sets/4/challenges/25)
Câu này hơi đơn giản quá nên mình hơi sợ làm sai?

Chúng ta bắt đầu bằng việc decrypt string từ set 1 challenge 7 và encrypt lại bằng AES-CTR:
```python
text = AES_decrypt(b'YELLOW SUBMARINE', b64decode(requests.get('https://cryptopals.com/static/challenge-data/25.txt').text))
random_key = generate_key()
keystream = encrypt_ctr(random_key, b'\x00' * len(text))
cipher = stream_xor(text, keystream)
```

Tạo edit API cho hacker: ở đây, bạn có thể thay đổi plaintext rồi encrypt lại cũng được, nhưng hạn chế generate lại keystream vì nó tốn rất nhiều thời gian.
```python
# API exposed to hacker
def edit(offset: int, newtext: bytes) -> int:
    return cipher[:offset] + \
            stream_xor(newtext, keystream[offset:offset + len(newtext)]) + \
            cipher[offset + len(newtext):]
```

Và do chúng ta có thể thay đổi plaintext và xem cipher mới, chúng ta có thể bruteforce toàn bộ plaintext từng chữ cái một: với mỗi khả năng của một chữ cái, chúng ta so sánh plaintext mới với plaintext cũ xem có giống nhau không.
```python
plaintext = b''
for i in trange(len(cipher)):
    for b in range(256):
        byte = bytes([b])
        if edit(i, byte) == cipher:
            plaintext += byte
            break
print(plaintext)
```

# [Challenge 26: CTR bitflipping](https://cryptopals.com/sets/4/challenges/26)

Do bài này giống như set 2 challenge 16, chúng ta clone code bên đó về — chỉ khác nhau là sử dụng CTR mode, và CTR không cần padding.
```python
random_key = generate_key()
def encrypt_data(s: str) -> bytes:
    s = r"comment1=cooking%20MCs;userdata=" + s.replace('=', '').replace(';', '') + r";comment2=%20like%20a%20pound%20of%20bacon"
    return encrypt_ctr(random_key, s.encode())

def is_admin(s: bytes) -> bool:
    return b'admin=true' in encrypt_ctr(random_key, s).split(b';')
```

Tương tự với challenge 16, chúng ta muốn sửa ciphertext sao cho
```
comment1=cooking                   comment1=cooking
%20MCs;userdata=                   %20MCs;userdata=
AAAAAAAAAAAAAAAA       --->        kwkt;admin=true;
;comment2=%20lik                   ;comment2=%20lik
e%20a%20pound%20                   e%20a%20pound%20
of%20bacon                         of%20bacon
```
Do stream ciphers chỉ XOR với keystream, chúng ta có thể thay thế cả block đó mà không tạo các bytes rác như với CBC.
```python
cipher = encrypt_data('A' * 16)
cipher = cipher[:32] + stream_xor(cipher[32:48],
    stream_xor(b'kwkt;admin=true;', b'A' * 16)
) + cipher[48:]
assert is_admin(cipher)
```

# [Challenge 27: Recover the key from CBC with IV=Key](https://cryptopals.com/sets/4/challenges/27)

Chúng ta sửa lại một chút code của challenge 16 để IV=Key, đồng thời cố định seed để sau check đáp án:
```python
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
```

Đằng nào string của chúng ta cũng thừa 3 block nên cũng không cần bắn gì vào `encrypt_data` cả:
```python
cipher = encrypt_data('')
is_admin(cipher[:16] + b'\x00' * 16 + cipher[:16] + cipher[48:])
```

Và đương nhiên Python sẽ nhả ra một đống lỗi:
```
ValueError: invalid literal for int() with base 10: b'comment1=cooking\x86H\xf5\xd6\xcf\xc6uG\r\xc0J\xf5/\xb5\x1c\nV)\x08\xc5\x89\xed\x82\xddi\x01\x86\xd3\xb4s\xd9\xfc\x1en\x80\xc2\x8d(\xe1\xc9\xed\xea\x0e\xe6\xc6\x87\xec\xa2of%20bacon'
```

Và làm như đúng những gì đã được hướng dẫn:
```python
decrypted = b'comment1=cooking\x86H\xf5\xd6\xcf\xc6uG\r\xc0J\xf5/\xb5\x1c\nV)\x08\xc5\x89\xed\x82\xddi\x01\x86\xd3\xb4s\xd9\xfc\x1en\x80\xc2\x8d(\xe1\xc9\xed\xea\x0e\xe6\xc6\x87\xec\xa2of%20bacon'
recovered = stream_xor(decrypted[:16], decrypted[32:48])
assert recovered == random_key
```

Vậy tại sao lại đúng? Chúng ta lại cần tới sự trợ giúp của giản đồ decrypt cho CBC:

![](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/600px-CBC_decryption.svg.png)

Rát đơn giản, chúng ta chỉ cần để ý block 1 và 3. Ta có:
```
P1' = KEY XOR dec(C1)
P3' =   0 XOR dec(C1)
```

Vì vậy ta có thể lấy lại được key bằng cách XOR 2 block "plaintext" đó. Thật là kỳ diệu!

# [Challenge 28: Implement a SHA-1 keyed MAC](https://cryptopals.com/sets/4/challenges/28)

Mình dùng và chỉnh sửa [file này](https://github.com/ajalt/python-sha1/blob/master/sha1.py) rồi lưu vào `sha1.py`, các bạn có thể tham khảo. Sau đó thì mất 3 dòng code nữa để implement HMAC:
```python
from sha1 import sha1
def sha1_hmac(msg: bytes) -> hex:
    return sha1(b'secret' + msg)
```

# [Challenge 29: Break a SHA-1 keyed MAC using length extension](https://cryptopals.com/sets/4/challenges/29)

Implement (chép từ source code) lại MD-compliant padding cho SHA-1:
```python
import struct
def sha1_pad(msg: bytes):
    pad = b'\x80'

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
    # is congruent to 56 (mod 64)
    pad += b'\x00' * ((56 - (len(msg) + 1) % 64) % 64)

    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    pad += struct.pack(b'>Q', len(msg) * 8)
    return msg + pad
```

Như đề bài đã nói, độ dài của prefix sẽ phải đoán; tuy nhiên chúng ta không có oracle, nên sẽ giả sử chúng ta đã đoán được độ dài:
```python
prefix_len = 6
```

Và thử hack nào:
```python
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
```

<sub>Phần này rõ ngắn/dễ nhưng quá error-prone đến mức mình mất một buổi chiều để làm.</sub>

# [Challenge 30: Break an MD4 keyed MAC using length extension](https://cryptopals.com/sets/4/challenges/30)

Mình sử dụng implementation ở [đây](https://gist.github.com/bonsaiviking/5644414).

Tương tự challenge 28, mình implement các hàm cần thiết trong đề bài:
```python
def md4_hmac(msg: bytes) -> bytes:
    return MD4(b'secret' + msg).hexdigest()
```

Định nghĩa hàm padding:
```python
def md4_pad(msg: bytes) -> bytes:
    ml = len(msg) * 8
    msg += b"\x80"
    msg += b"\x00" * (-(len(msg) + 8) % 64)
    msg += struct.pack("<Q", ml)
    return msg
```

Và crack giống i xì challenge 29:
```python
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
```

# [Challenge 31: Implement and break HMAC-SHA1 with an artificial timing leak](https://cryptopals.com/sets/4/challenges/31)

Việc đầu tiên cần làm là viết server code — mình viết bằng Flask vì mình viết Flask quen rồi:
```python
from time import sleep
from flask import Flask, request
from sha1 import sha1

def insecure_compare(h1: str, h2: str) -> bool:
    if len(h1) != len(h2): return False
    for c1, c2 in zip(h1, h2):
        if c1 != c2:
            return False
        sleep(0.05)
    return True

app = Flask(__name__)
@app.route('/test')
def check_hash():
    f = request.args.get('file')
    h = request.args.get('signature')
    if f is None or h is None:
        return 'bad', 400
    real = sha1(f.encode())
    if insecure_compare(h, real):
        return 'ok', 200
    else:
        return 'ng', 500

if __name__ == '__main__':
    app.run(port=9000)
```

Chúng ta sẽ thử tìm hash của chuỗi *vierundzwanzigsieben* — giờ là code query server từ client. Chúng ta nhận vào 20 bytes (vì đó là kích cỡ đầu ra của SHA-1), và trả về liệu hash đó có đúng không, và thời gian cần thiết để server trả về.
```python
def candidate2hex(candidate):
    # convert [0-16] to [0-9a-f]
    return ''.join(hex(c)[-1] for c in candidate)

def check_hash(candidate):
    # candidate is 20 bytes in a list
    hash_ = candidate2hex(candidate)
    res = requests.get('http://localhost:9000/test', {
        'file': 'vierundzwanzigsieben',
        'signature': hash_
    })
    return res.ok, res.elapsed.total_seconds()
```

Sau đó chúng ta bruteforce dần từng chữ cái: nếu thử chữ cái đó mà lâu hơn lần trước, nghĩa là hàm so sánh phải so sánh thêm 1 chữ cái, nghĩa là chữ cái vừa rồi là đúng.

Trường hợp thử đầu tiên cho từng chữ cái thì phức tạp hơn: có thể là chữ cái đó (0) đã đúng luôn rồi. Vì vậy, ta phải thử với trường hợp 1 nữa. Sẽ xảy ra 3 trường hợp:
- Nếu thời gian 2 trường hợp bằng nhau, nghĩa là không trường hợp nào đúng cả: ta thử tiếp từ trường hợp 2.
- Nếu thời gian 2 trường hợp khác nhau, nghĩa là trường hợp lâu hơn là trường hợp đúng: ta chọn đáp án đúng, và chuyển sang chữ cái tiếp theo.

Ngoài ra, mình còn sử dụng một số trick nữa: 
- Để phòng trường hợp mỗi lần đo có chênh lệch, phải chênh ít nhất 3ms mới tính là có comparison mới.
- Thử mỗi chữ số `0-9a-f` 2 lần, nếu không tìm ra đáp án thì backtrack lại thử lại chữ số trước, vì khả năng lớn là sai từ trước rồi.
- Nếu đến chữ cái cuối cùng mà không ra OK, thử lại chữ cái cuối cùng.

```python
candidate = [0] * 40
last_elapsed = None
idx = 0
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

        if abs(elapsed_ - elapsed) < 3e-2:
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
        if elapsed > last_elapsed + 3e-2:
            last_elapsed = elapsed
            if idx < 39:
                idx += 1
            # false positive, try again
            else:
                candidate[idx] = 0

        elif elapsed < last_elapsed - 3e-2:
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
```
Code này sẽ rất lâu đó. Trường hợp tệ nhất: 40 chữ cái $\times$ 0.05s là 2s mỗi lần thử, với 16 lần thử mỗi chữ cái, là tổng cộng hơn 21 phút lận. Chưa kể, detect chữ cái sai hoài nên backtrack liên tục nữa. Chờ cả tháng luôn.

# [Challenge 32: Break HMAC-SHA1 with a slightly less artificial timing leak](https://cryptopals.com/sets/4/challenges/32)

Với thời gian thực chênh lệch quá bé (5ms/it), thì các lần đo thời gian sẽ bị nhiễu rất lớn (so sánh tương đối) bới các yếu tố ngoại lai. Vậy, phải làm gì để giảm thiểu các sai số? Sử dụng Central Limit Theorem! Chúng ta chạy thí nghiệm càng nhiều lần thì trung bình kết quả càng chính xác. Ở đây mình thử chạy mỗi test 10 lần, nhưng để chắc kèo thì bạn có thể chơi luôn 30 lần theo guidelines của các statisticians.

```python
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
```

***
**<div align="center">Nghe bảo từ set sau sẽ khó lên trông thấy...</div>**
***