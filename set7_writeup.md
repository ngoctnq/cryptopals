<sup>Đây là một bài trong series [Cùng giải Cryptopals!](https://viblo.asia/s/cung-giai-cryptopals-68Z00nw9ZkG).<br>Các bạn nên tự làm hoặc vừa đọc vừa làm thay vì đọc lời giải trực tiếp.</sup>
***
**<div align="center">Không chần chừ gì nữa, hãy bắt đầu nào!</div>**
***

# [Challenge 49: CBC-MAC Message Forgery](https://cryptopals.com/sets/6/challenges/49)

Chúng ta viết code server trước vì nó dễ (xin lỗi các bạn không có GUI đâu vì đến lúc tấn công thì cũng đâu có ai dùng GUI). Trong server có bao gồm một hàm chuyên đi ký, chỉ dành cho những người có quyền (hiện tại là tất cả mọi người, nên nếu ai clone code này về làm server nhớ sửa nhé). <sup>/s</sup>
```python:chall49_server.py
from flask import Flask, request
from utils import generate_key, AES_encrypt
import re

app = Flask(__name__)
key = generate_key(16)

@app.route('/sign', methods=['POST'])
def sign():
    # some sick authorization here
    if False: return 'NG', 403
    try:
        data = request.json()
        msg = f"from={data['acc_from']}&to={data['acc_to']}&amount={data['amount']}".encode()
    except:
        return 'NG', 400
    iv = generate_key()
    mac = AES_encrypt(key, msg, 'cbc', iv)[-16:]
    return msg + iv + mac

@app.route('/send', methods=['POST'])
def send_monii():
    data = request.data
    if len(data) <= 32: return 'NG', 400
    mac = data[-16:]
    iv = data[-32:-16]
    msg = data[:-32]
    if AES_encrypt(key, msg, 'cbc', iv)[-16:] != mac:
        return 'NG', 400
    try:
        # the three vals returned are acc_from, acc_to, and amount
        re.match(r'^from=(\d+)&to=(\d+)&amount=(\d+)$', msg.decode()).groups()
    except:
        return 'NG', 400
    return 'OK', 200

if __name__ == '__main__':
    app.run(port=9000, debug=True)
```

Giả sử ban đầu attacker có 2 account với IDs là 6 và 9 (nice), và account cần hack có ID là 8. Tin nhắn chúng ta có MAC là
```
from=6&to=9&amou
nt=1000000\x06\x06\x06\x06\x06\x06
```

Tin nhắn chúng ta cần MAC là
```
from=8&to=9&amou
nt=1000000\x06\x06\x06\x06\x06\x06
```

Đến hẹn lại lên, như các bài trước, đây là biểu đồ encryption của CBC:

![](https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/600px-CBC_encryption.svg.png)

Nhìn qua giản đồ chúng ta có thể thấy để ciphertext không đổi gì, ta chỉ cần sửa các bit ở "plaintext" block 1 để ra payload chúng ta muốn, và sửa IV để ciphertext của block 1 không thay đổi. Ở đây, chúng ta cần thay đổi byte thứ 6 từ `\x36` (`ord('6')`) thành `\x38` (`ord('8')`).

```python
valid = requests.post('http://localhost:9000/sign', json={
    'acc_from': 6, 'acc_to': 9, 'amount': 1000000
}).content
assert requests.post('http://localhost:9000/send', data=valid).status_code == 200

payload = list(valid)
payload[5] = ord('8')
payload[5 + 16 * 2] ^= ord('6') ^ ord('8')
payload = bytes(payload)
assert payload[:-32] == b'from=8&to=9&amount=1000000'
assert requests.post('http://localhost:9000/send', data=valid).status_code == 200
```

Để ý rằng tấn công này chỉ hoạt động nếu
- `from` và `to` nằm trong cùng block đầu tiên
- Tổng số chữ số của `from` và `to` giữa cũ và mới không thay đổi

Gói gọn cả 2 yêu cầu trên, block 2 trở đi phải không thay đổi.

Cho phần 2 của bài này, chúng ta lại viết thêm code server:
```python:chall49_server.py
@app.route('/sign2', methods=['POST'])
def sign2():
    # some sick authorization here
    if False: return ('NG', 403)
    try:
        data = request.json
        msg = f"from={data['acc_from']}&txlist=" + \
              ';'.join([f'{x[0]}:{x[1]}' for x in data['txlist'].items()])
        msg = msg.encode()
    except:
        return 'NG', 400
    mac = AES_encrypt(key, pkcs7_pad(msg), 'cbc')[-16:]
    return msg + mac

@app.route('/send2', methods=['POST'])
def send2():
    data = request.data
    if len(data) <= 16: return 'NG', 400
    mac = data[-16:]
    msg = data[:-16]
    if AES_encrypt(key, pkcs7_pad(msg), 'cbc')[-16:] != mac:
        return 'NG', 400
    try:
        # learn regex, it's fun
        re.match(rb'^from=(\d+)&txlist=([^:;]+):([^;]+)(?:;([^:;]+):([^;]+))*$', msg).groups()
    except:
        return 'NG', 400
    return 'OK', 200
```
Các bạn có thể thấy code regex đã được sửa từ việc bắt số sang thành bắt tất cả mọi thứ (và phó mặc sanitization sau). Có 2 lý do:
- Ban đầu mình giả thiết là số tiền là một số nguyên, nhưng thực thế không chắc là như vậy. Mình có thể viết thêm regex để handle phần lẻ đằng sau, nhưng thôi.
- Đề bài hướng dẫn sử dụng MAC làm IV cho tin nhắn extension. Điều đó đòng nghĩa với việc cách tấn công này sẽ không thể xoá được padding đang lưu trong các transaction cũ của nạn nhân, và sẽ trở thành byte rác. Nếu server auto reject request lúc nhận được rác thì attack này sẽ không thành.

Quay lại đề bài, chúng ta intercept được tin nhắn của người dùng như sau: nạn nhân ID 8 gửi 123 thiên hà đồng đến account ID 7:
```
from=8&txlist=7:
123\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d
```
Request này kẻ tấn công nhận được, và lấy được kết quả $\mathrm{MAC}_0$.

Attacker có thể lấy được MAC cho tin nhắn sau (do những account đó họ quản lý):
```
from=6&txlist=0:
1;9:1000000\x05\x05\x05\x05\x05
```
Đây sẽ là MAC của payload cuối cùng.


Chúng ta sẽ sử dụng tấn công [này trên Wikipedia](https://en.wikipedia.org/wiki/CBC-MAC#Security_with_fixed_and_variable-length_messages) (thú thực bài này khó quá mình đã phải đọc thay vì tự nghĩ ra).

Chúng ta sẽ sửa "plaintext" của chúng ta thành
```
from=8&txlist=7:
123\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d
[ 16 bytes rác ]        <-          from=6&txlist=0: XOR MAC_0
1;9:1000000\x05\x05\x05\x05\x05
```

Nhắc lại cái diagram thần thánh của CBC:

![](https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/600px-CBC_encryption.svg.png)

Để ý ở block 3 của payload plaintext, block 1 của attacker XOR $\mathrm{MAC_0}$ sẽ được encrypt với IV là $\mathrm{MAC_0}$, chính là ciphertext của block trước (block 2 của victim). Điều này tương đương với block 1 của attacker's plaintext được encrypt với IV 0, khiến ciphertext không đổi. Hệ quả là block 4 encrypted với cùng IV như bên attacker, và MAC của payload sẽ giống với MAC của attacker.

```python
victim_mac = requests.post('http://localhost:9000/sign2', json={
    'acc_from': 8,
    'txlist': {
        7: 123
    }
}).content
assert requests.post('http://localhost:9000/send2', data=victim_mac).status_code == 200

# get victim's MAC
victim_content = victim_mac[:-16]
victim_mac = victim_mac[-16:]

# get attacker's MAC
attacker_mac = requests.post('http://localhost:9000/sign2', json={
    'acc_from': 6,
    'txlist': {
        0: 1,
        9: 1000000
    }
}).content
assert requests.post('http://localhost:9000/send2', data=attacker_mac).status_code == 200

attacker_content = attacker_mac[:-16]
attacker_mac = attacker_mac[-16:]

# craft payload
payload = pkcs7_pad(victim_content) + stream_xor(attacker_content[:16], victim_mac) + attacker_content[16:] + attacker_mac
assert requests.post('http://localhost:9000/send2', data=payload).status_code == 200

# make sure payload sends me 1M bucks
params = dict(map(lambda x: x.split(b'='), payload.split(b'&')))
assert params[b'from'] == b'8' and b'9:1000000' in params[b'txlist']
```

Để tránh bị tấn công kiểu này, có 2 cách chống (lấy từ Wiki nốt):
- Bao gồm độ dài tin nhắn ở đầu chuỗi cần MAC.
- Mã hoá MAC đầu ra bằng một key khác.

# [Challenge 50: Hashing with CBC-MAC](https://cryptopals.com/sets/6/challenges/50)

Đầu tiên là tạo hàm hash cái đã:
```python
def hash_cbc(msg: bytes) -> bytes:
    return AES_encrypt(b"YELLOW SUBMARINE", pkcs7_pad(msg), 'cbc')[-16:]
```

Các block của XSS gốc là
```
alert('MZA who w
as that?');\n\x04\x04\x04
```

Làm gần như tương tự bài trước, chúng ta sẽ tạo payload
```
alert('Ayo, the[space]
Wu is back!');//
alert('MZA who w        XOR hash(above)
as that?');\n\x04\x04\x04
```

Thay vì việc block thứ 3 có IV là cipher của block thứ 2, chúng ta sẽ XOR nó với cipher đó để tương ứng với 0 IV (giống block đầu của chuỗi gốc).
```python
original = b"alert('MZA who was that?');\n"
assert hexlify(hash_cbc(original)) == b'296b8d7cb78a243dda4d0a61d33bbdd1'

modified = b"alert('Ayo, the Wu is back!');//"
modified += \
    stream_xor(
        original[:16],
        AES_encrypt(b"YELLOW SUBMARINE", modified, 'cbc')[-16:]
    ) + original[16:]
print(hexlify(hash_cbc(modified)), b'296b8d7cb78a243dda4d0a61d33bbdd1')
```

Mình sẽ không làm extra credit vì lười :) Và thực tế thì cũng có vẻ không cần dùng đến.

**Easter egg**: MZA là Method-Man, một thành viên của nhóm rap nổi tiếng Wu-Tang Clan. XSS string trong bài
> MZA who was that?

và
> Ayo, the Wu is back!

là 2 câu trong lời bài hát [Wu-Tang Clan Ain’t Nuthing ta Fuck Wit của Wu-Tang Clan](https://www.youtube.com/watch?v=HnOZea4Zgbc).

# [Challenge 51: Compression Ratio Side-Channel Attacks](https://cryptopals.com/sets/6/challenges/51)

Trước hết, chúng ta viết compression oracle:
- Cho phiên bản dùng CTR/Streaming XOR: độ dài chuỗi sẽ được giữ nguyên.
```python
def compression_oracle(P: bytes):
    req = f'POST / HTTP/1.1\nHost: hapless.com\nCookie: sessionid={sessionid}\nContent-Length: {len(P)}\n'.encode() + P
    return len(AES_encrypt(generate_key(), compress(req), 'ctr', generate_key(8)))
```
- Cho phiên bản dùng CBC: độ dài chuỗi sẽ bị pad đến bội số của 16 tiếp theo.
```python
def compression_oracle(P: bytes):
    req = f'POST / HTTP/1.1\nHost: hapless.com\nCookie: sessionid={sessionid}\nContent-Length: {len(P)}\n'.encode() + P
    return len(AES_encrypt(generate_key(), pkcs7_pad(compress(req)), 'cbc', generate_key(16)))
```

Và code này sẽ giải được cả 2 phiên bản:
```python
payload_prefix = 'sessionid='
charset = ascii_letters + digits + '+='
candidates = ['']
final_candidate = None

while not final_candidate:
    min_compressed = None
    min_candidates = []
    for prefix, char in product(candidates, charset):
        if '=' in prefix and char != '=': continue
        sessid = prefix + char
        payload = (payload_prefix + sessid).encode()
        compressed_size = [compression_oracle(b'\n'.join([payload] * 2 ** i)) for i in range(4)]
        if min_compressed is None:
            min_compressed = compressed_size
            min_candidates = [sessid]
        elif min_compressed >= compressed_size:
            if min_compressed == compressed_size:
                min_candidates.append(sessid)
            else:
                min_compressed = compressed_size
                min_candidates = [sessid]
    # filter the candidates
    candidates = []
    for candidate in min_candidates:
        if '=' in candidate:
            if len(min_candidates) < 50:
                final_candidate = b64encode(b64decode(candidate + '==')).decode()
                break
        else:
            candidates.append(candidate)

assert sessionid == final_candidate
```

Về cơ bản thì nội dung code giống như trong hướng dẫn đề bài. Tuy nhiên, để ý rằng hiện tại trong code mình có một số nâng cấp theo các heuristics:
- Chỉ chấp nhận đáp án nếu số trường hợp cần xem xét tiếp theo ít hơn 50. Con số 50 ở đây được chọn bừa, nó thấp hơn 63 ký tự có thể thử mỗi chữ cái.
- Thử lấy compressed size với nhiều khả năg lặp lại. Với mỗi string, code sẽ lấy kết quả compressed size với các payload bao gồm 1/2/4/8 chuỗi session ID lặp lại. Chúng ta biết được rằng ở settings nào thì size của chuỗi đúng cũng bé hơn hoặc bằng chuỗi sai; và làm thế sẽ giúp chúng ta giảm được sai số khi nén bit level bị làm tròn theo byte *và* làm tròn lên bội số của 16 bytes khi sử dụng CBC.
- Dừng ở `=` vì base64 thường có padding. Nếu chuỗi ban đầu không cần padding thì có thể sẽ không trả về kết quả (vì chúng ta có luôn có thể điền tiếp chữ cái để tạo ra chuỗi base64 mới).

**Easter egg:** Cookie sau khi đã decode từ base64 là
> Never reveal the Wu-Tang Secret!

là lyrics bài [You Don't Want To Fuck With Me của Ol' Dirty Bastard](https://www.youtube.com/watch?v=OKk2It4FwCc).

# [Challenge 52: Iterated Hash Function Multicollisions](https://cryptopals.com/sets/6/challenges/52)

Đầu tiên là các hàm tạo hash sử dụng AES-128: Trong đó, hàm `f` tạo ra hash dài 16 bit, và hàm $g$ tạo hash dài 24 bit. Ngoài ra, do mỗi vòng lặp sẽ ra được hash mới dài 128 bit, hash trong quá trình sẽ bị cắt từ bên trái vào, và pad từ bên phải qua, lúc cần thiết.
```python
def f(msg: bytes, h: bytes = b'\x06\x09'):
    # output is 16 bit/2 bytes
    assert len(h) == 2
    assert len(msg) % 16 == 0
    for i in range(0, len(msg), 16):
        # pads on the right, truncate the left
        h = AES_encrypt(msg[i:i+16], pkcs7(h, 14))[-2:]
    return h

def g(msg: bytes, h: bytes = b'\x04\x02\x00'):
    # output is 24 bit/3 bytes
    assert len(h) == 3
    assert len(msg) % 16 == 0
    for i in range(0, len(msg), 16):
        # pads on the right, truncate the left
        h = AES_encrypt(msg[i:i+16], pkcs7(h, 13))[-3:]
    return h
```

Tạo ra các counter để xem chúng ta phải thử mất bao nhiêu lần:
```python
f_count = 0
g_count = 0
```

Generate ra các hash collision cho `f`:
```python
# generate 2^12 hash collisions (i.e. 12 blocks)
fragments = []
hashes = [b'\x06\x09']
for i in range(12):
    found = {}
    for block in product(range(256), repeat=16):
        f_count += 1
        block = bytes(block)
        hash_ = f(block, hashes[i])
        if hash_ in found:
            found[hash_].append(block)
            fragments.append(found[hash_])
            hashes.append(hash_)
            break
        else:
            found[hash_] = [block]
print('Generating 2^12 f-collisions took', f_count, 'tries.')
```

Và check từng chuỗi một xem có collide dưới `g` không. Chú ý, với các $i$ khác nhau thì sau khi ghép $i$ blocks đầu tiên lại ra các `f`-hash khác nhau, nên khi check collision dưới `g` nhớ reset danh sách hash mỗi lần thêm block.
```python
# check for g collisions
found = False
trials = [b'']
for i in range(12):
    for j in range(len(trials)):
        trials.append(trials[j] + fragments[i][0])
        trials[j] += fragments[i][1]
    g_hashes = {}
    for msg in trials:
        g_count += 1
        g_hash = g(msg)
        if g_hash in g_hashes:
            msg_ = g_hashes[g_hash]
            found = True
            break
        else:
            g_hashes[g_hash] = msg
    if found: break
if found:
    print('Found collision!')
    assert f(msg) == f(msg_) and g(msg) == g(msg_)
    print('Total calls to check for g-collisions:', g_count)
```

Và nếu không chạy thì chúng ta thử tiếp:
```python
else:
    print('Collision for g not found. Generating more...', g_count)
    i = 12
    while not found:
        # generate new f
        found = {}
        for block in product(range(256), repeat=16):
            f_count += 1
            block = bytes(block)
            hash_ = f(block, hashes[i])
            if hash_ in found:
                found[hash_].append(block)
                fragments.append(found[hash_])
                hashes.append(hash_)
                break
            else:
                found[hash_] = [block]
        # recheck g collisions
        for j in range(len(trials)):
            trials.append(trials[j] + fragments[i][0])
            trials[j] += fragments[i][1]
        g_hashes = {}
        for msg in trials:
            g_count += 1
            g_hash = g(msg)
            if g_hash in g_hashes:
                msg_ = g_hashes[g_hash]
                found = True
                break
            else:
                g_hashes[g_hash] = msg
        if found:
            print('Found collision!')
            assert f(msg) == f(msg_) and g(msg) == g(msg_)
            print('Total calls to generate f-collisions:', f_count, 'tries.')
            print('Total calls to check for g-collisions:', g_count)
        else:
            # life goes on
            i += 1
```

Kết quả chúng ta có (không có random nên bạn có thể reproduce được):
```
Generating 2^12 f-collisions took 3454 tries.
Found collision!
Total calls to check for g-collisions: 4593
```

Lý do tại sao `g` dễ ra collision như vậy là bởi vì một tấn công có tên là [Birthday Attack](https://en.wikipedia.org/wiki/Birthday_attack). Khái niệm này đọc 1-2 lần có thể vẫn hơi khó hiểu, có gì bạn có thể để nó ngấm một chút nha. Đại khái ý tưởng chính là như sau: trong một lớp học (tầm 30-40 người?), tìm được một người cùng ngày sinh với mình rất khó (vì chốt ngày sinh của họ), nhưng tìm hai người có cùng ngày sinh với nhau thì dễ hơn rất nhiều (vì ngày sinh đó không bị cố định). Tìm hai chuỗi có cùng hash cũng vậy.

# [Challenge 53: Kelsey and Schneier's Expandable Messages](https://cryptopals.com/sets/6/challenges/53)

Có một điều bạn nên nhớ: padding của bài này không giống như challenge 52 (PKCS5/7), mà là padding của Merkle-Damgard hash — nghĩa là, padding có phụ thuộc vào độ dài tin nhắn, và yêu cầu second preimage của chúng ta phải có độ dài giống với tin nhắn ban đầu. Vì vậy, cho dù có thể implement tấn công này với MD4/5/SHA-1, chúng ta sẽ tấn công với hàm hash đồ chơi từ challenge trước, nhưng với block size là 8 bytes và output là 4 bytes cho nhanh (vì block của MD5/SHA-1 đều rất lớn: 64 bytes).

Đầu tiên chúng ta implement lại hàm hash: mình có chỉnh sửa là nếu hash một tin nhắn đầy đủ (`partial=False`) thì sẽ trả về tất cả các state của hash từ đầu đến cuối.
```python
# given block_size, hash_size, original_state
assert 16 % block_size == 0
def toy_hash(msg: bytes, h: bytes = original_state, partial=True):
    assert len(h) == hash_size
    if partial:
        assert len(msg) % block_size == 0
    else:
        msg = pkcs7(msg, block_size - (len(msg) % block_size))
        states = []
    for i in range(0, len(msg), block_size):
        # pads on the right, truncate the left
        h = AES_encrypt(msg[i : i + block_size] * (16 // block_size),
                        pkcs7(h, 16 - hash_size))[-hash_size:]
        if not partial:
            states.append(h)
    if partial:
        return h
    else:
        return states
```

Hàm kiếm hash collision từ 2 state khác nhau:
```python
def get_collision(state1, state2):
    hashes1 = {}
    hashes2 = {}
    for block in product(range(256), repeat=block_size):
        block = bytes(block)
        hash1 = toy_hash(block, state1)
        hash2 = toy_hash(block, state2)
        if hash1 in hashes1: continue
        else: hashes1[hash1] = block
        if hash2 in hashes2: continue
        else: hashes2[hash2] = block
        union = hashes1.keys() - hashes2.keys()
        if len(union) >= 1:
            state = union.pop()
            return hashes1[state], hashes2[state], state
```

Tạo tin nhắn cần collide dài $2^{10}$ blocks (+ ít dư):
```python
# given msg_log_len
# if msg_log_len = 10, then it's 1024 blocks + less than a block
original = generate_key(2 ** msg_log_len * block_size + randint(1, block_size - 1))
states = dict((v, k) for k, v in enumerate(toy_hash(original, partial=False)) if msg_log_len <= k < 2 ** msg_log_len)
```

Tạo ra các block để nối lại thành expandable message:
```python
# build the expandable message
state = original_state
messages = []
for i in range(msg_log_len):
    prefix = generate_key(2 ** (msg_log_len - i - 1) * block_size)
    state2 = toy_hash(prefix, state)
    msg1, msg2, state = get_collision(state, state2)
    messages.append([msg1, prefix + msg2])
```

Tìm block cầu nối: đây là phần sẽ chiếm nhiều thời gian nhất, vì tìm được collision hay không phụ thuộc rất nhiều vào nhân phẩm. Lúc tìm được block cầu nối, code sẽ nối các phần cần thiết để trả về luôn chuỗi cùng hash:
```python
# find the connector block
for block in product(range(256), repeat=block_size):
    block = bytes(block)
    hash_ = toy_hash(block, state)
    if hash_ in states:
        block_count = states[hash_]
        # get the expandable message of desired length
        crafted = b''
        crafted_block_count = block_count - msg_log_len
        for i, (c1, c2) in enumerate(messages):
            if crafted_block_count < 2 ** (msg_log_len - i - 1):
                crafted += c1
            else:
                crafted += c2
                crafted_block_count -= 2 ** (msg_log_len - i -1)
        crafted += block + original[block_size * (block_count + 1):]
        break
```

Và check xem code chúng ta có chạy đúng không:
```python
assert original != crafted and len(original) == len(crafted) and \
    toy_hash(original, partial=False)[-1] == toy_hash(crafted, partial=False)[-1]
```

# [Challenge 54: Kelsey and Kohno's Nostradamus Attack](https://cryptopals.com/sets/6/challenges/54)

Về cơ bản thì tấn công này khá giống với challenge 52, chỉ khác ở chỗ là chúng ta có thể chọn được prefix ban đầu: ở challenge 52, $2^n$ tin nhắn đều nhìn như rác do ngẫu nhiên, nhưng ở đây các tin nhắn sẽ có khoảng đầu có nghĩa (được chọn). Sử dụng các primitives có sẵn từ challenge 53 ở trên, bài này sẽ trở nên rất dễ:
```python:pseudocode
# for some fixed k
k = 10
# and some initial messages of the same length filling a whole block
msgs = [...]
lens = map(len, msgs)
assert len(msg) == 2 ** k and max(lens) == min(lens) and min(lens) % block_size == 0
msgs = [msgs]
hashes = [list(map(hash_fn, msgs))]
tails = []
for i in range(k):
    tail = []
    states = []
    for j in range(0, 2 ** i, 2):
        msg1, msg2, state = get_collision(hashes[i][j], hashes[i][j+1])
        tail.append(msg1)
        tail.append(msg2)
        states.append(state)
    tails.append(tail)
    hashes.append(states)
# then do things with hashes[-1][-1]
```

# [Challenge 55: MD4 Collisions](https://cryptopals.com/sets/6/challenges/55)

Chúng ta implement trước vài hàm giúp đỡ, trong đó có
- Lấy một bit tại một vị trí nào đó trong một số nguyên,
- Sửa các bit theo yêu cầu; yêu cầu đó là một `dict` lưu vị trí cần sửa và giá trị mới tại vị trí đó,
- Tính state mới sau 1 loop round 1,
- Sửa block tin nhắn để state mới đúng với yêu cầu của thuật toán.
```python
def bit_at(num, i):
    # 0 is least significant
    return (num >> i) & 1
def correct(num, rules):
    # rules is dict({idx, bit_value})
    for idx, val in rules.items():
        assert val in (0, 1)
        if val == 0:
            num ^= (bit_at(num, idx) << idx)
        else:
            num |= (1 << idx)
    return num
def round1(a, b, c, d, lrot, m):
    return leftrotate((a + F(b, c, d) + m) & 0xFFFFFFFF, lrot)
def fix1(a, b, c, d, lrot, old_a):
    return (leftrotate(a, 32 - lrot) - old_a - F(b, c, d)) % 0x100000000
```

Do không implement toàn bộ các điều kiện nên code chỉ đơn giản thế này thôi — trong đó hiện tại đã xóc đĩa song song để tăng tốc bruteforce:
```python
from multiprocessing import Process, cpu_count, Value
count = Value('i', 0)

print('Running attack', end='', flush=True)
def search_thread():
    global count
    while True:
        with count.get_lock():
            if count.value == -1 or count.value > 2 ** 30: break
            count.value += 1
            if count.value % (1 << 16) == 0: print('.', end='', flush=True)
            if count.value % (9 << 19) == 0: print()
        original = generate_key(64)
        a, b, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
        m = list(struct.unpack("<16I", original))

        # condition the collided msg
        # rule 1
        old_val = a
        a = round1(a, b, c, d, 3, m[0])
        a = correct(a, {
            6: bit_at(b, 6)
        })
        m[0] = fix1(a, b, c, d, 3, old_val)
        # rule 2
        old_val = d
        d = round1(d, a, b, c, 7, m[1])
        d = correct(d, {
            6: 0,
            7: bit_at(a, 7),
            10: bit_at(a, 10)
        })
        m[1] = fix1(d, a, b, c, 7, old_val)
        # rule 3
        old_val = c
        c = round1(c, d, a, b, 11, m[2])
        c = correct(c, {
            6: 1,
            7: 1,
            10: 0,
            25: bit_at(d, 25)
        })
        m[2] = fix1(c, d, a, b, 11, old_val)
        # rule 4
        old_val = b
        b = round1(b, c, d, a, 19, m[3])
        b = correct(b, {
            6: 1,
            7: 0,
            10: 0,
            25: 0
        })
        m[3] = fix1(b, c, d, a, 19, old_val)
        # rule 5
        old_val = a
        a = round1(a, b, c, d, 3, m[4])
        a = correct(a, {
            7: 1,
            10: 1,
            25: 0,
            13: bit_at(b, 13)
        })
        m[4] = fix1(a, b, c, d, 3, old_val)
        # rule 6
        old_val = d
        d = round1(d, a, b, c, 7, m[5])
        d = correct(d, {
            13: 0,
            18: bit_at(a, 18),
            19: bit_at(a, 19),
            20: bit_at(a, 20),
            21: bit_at(a, 21),
            25: 1
        })
        m[5] = fix1(d, a, b, c, 7, old_val)
        # rule 7
        old_val = c
        c = round1(c, d, a, b, 11, m[6])
        c = correct(c, {
            12: bit_at(d, 12),
            13: 0,
            14: bit_at(d, 14),
            18: 0,
            19: 0,
            20: 1,
            21: 0
        })
        m[6] = fix1(c, d, a, b, 11, old_val)
        # rule 8
        old_val = b
        b = round1(b, c, d, a, 19, m[7])
        b = correct(b, {
            12: 1,
            13: 1,
            14: 0,
            16: bit_at(c, 16),
            18: 0,
            19: 0,
            20: 0,
            21: 0
        })
        m[7] = fix1(b, c, d, a, 19, old_val)
        # rule 9
        old_val = a
        a = round1(a, b, c, d, 3, m[8])
        a = correct(a, {
            12: 1,
            13: 1,
            14: 1,
            16: 0,
            18: 0,
            19: 0,
            20: 0,
            22: bit_at(b, 22),
            21: 1,
            25: bit_at(b, 25)
        })
        m[8] = fix1(a, b, c, d, 3, old_val)
        # rule 10
        old_val = d
        d = round1(d, a, b, c, 7, m[9])
        d = correct(d, {
            12: 1,
            13: 1,
            14: 1,
            16: 0,
            19: 0,
            20: 1,
            21: 1,
            22: 0,
            25: 1,
            29: bit_at(a, 29)
        })
        m[9] = fix1(d, a, b, c, 7, old_val)
        # rule 11
        old_val = c
        c = round1(c, d, a, b, 11, m[10])
        c = correct(c, {
            16: 1,
            19: 0,
            20: 0,
            21: 0,
            22: 0,
            25: 0,
            29: 1,
            31: bit_at(d, 31)
        })
        m[10] = fix1(c, d, a, b, 11, old_val)
        # rule 12
        old_val = b
        b = round1(b, c, d, a, 19, m[11])
        b = correct(b, {
            19: 0,
            20: 1,
            21: 1,
            22: bit_at(c, 22),
            25: 1,
            29: 0,
            31: 0
        })
        m[11] = fix1(b, c, d, a, 19, old_val)
        # rule 13
        old_val = a
        a = round1(a, b, c, d, 3, m[12])
        a = correct(a, {
            22: 0,
            25: 0,
            26: bit_at(b, 26),
            28: bit_at(b, 28),
            29: 1,
            31: 0
        })
        m[12] = fix1(a, b, c, d, 3, old_val)
        # rule 14
        old_val = d
        d = round1(d, a, b, c, 7, m[13])
        d = correct(d, {
            22: 0,
            25: 0,
            26: 1,
            28: 1,
            29: 0,
            31: 1
        })
        m[13] = fix1(d, a, b, c, 7, old_val)
        # rule 15
        old_val = c
        c = round1(c, d, a, b, 11, m[14])
        c = correct(c, {
            18: bit_at(d, 18),
            22: 1,
            25: 1,
            26: 0,
            28: 0,
            29: 0
        })
        m[14] = fix1(c, d, a, b, 11, old_val)
        # rule 16
        old_val = b
        b = round1(b, c, d, a, 19, m[15])
        b = correct(b, {
            18: 0,
            25: 1,
            26: 1,
            28: 1,
            29: 0
        })
        m[15] = fix1(b, c, d, a, 19, old_val)

        # edit old msg to have desired conditions
        msg1 = struct.pack("<16I", *m)

        # craft the collision
        m[1] = (m[1] + (1 << 31)) % 0x100000000
        m[2] = (m[2] + (1 << 31) - (1 << 28)) % 0x100000000
        m[12] = (m[12] - (1 << 16)) % 0x100000000
        msg2 = struct.pack("<16I", *m)
        if MD4(msg1).hexdigest() == MD4(msg2).hexdigest():
            print('\nFound a collision!')
            print(msg1)
            print(msg2)
            with count.get_lock():
                count.value = -1
            break

procs = [Process(target=search_thread) for _ in range(cpu_count())]
for p in procs:
    p.start()
for p in procs:
    p.join()
```

Trong code, mình có implement 16 rules đầu tiên, vì nó chỉ đụng vào round đầu tiên. Round thứ 2 khi sửa sẽ đụng vào các phần của tin nhắn đã sửa từ round 1 nên phức tạp và mình không làm :) Đằng nào cũng nhiều gấp 16 lần số rule trong hướng dẫn rồi.

Sau 3 tiếng chạy code trên 3 server khoẻ hơn Phạm Văn Mách cùng lúc:
```
Found a collision!
b'\x07\xa1"\x1c\x10\xba(#\xc3\x1d?\xbb\xf9:K\x18\x0c\xa2\x9f\x8d\xa3\x9d\xf9\xb9\x04\x0f\xcf\xa7!zi\x90\x8d\xaeS\xba\xd9\x0b\xa0~\xe9p\xcckg\xa0\x8e,*\xdc\xa9\x8eX5\xf5<\xa3\x80\xce\xd3\x81\x89}\x00'
b'\x07\xa1"\x1c\x10\xba(\xa3\xc3\x1d?+\xf9:K\x18\x0c\xa2\x9f\x8d\xa3\x9d\xf9\xb9\x04\x0f\xcf\xa7!zi\x90\x8d\xaeS\xba\xd9\x0b\xa0~\xe9p\xcckg\xa0\x8e,*\xdc\xa8\x8eX5\xf5<\xa3\x80\xce\xd3\x81\x89}\x00'
Taken 33350994 trials.
```
Tầm $2^{25}$ cú xóc đĩa.

Thêm một kết quả khác cho dân chơi:
```
Found a collision!
b"'N]\xb7\x81Cr\x8c\n\xb4\x8a\x83\xecx\xf1\nC\x90\xc1\x9d \x0e>\x95_\xae\x8a\xd1dp\x9d\x10\xf2\xf1\x86\x06\xbe\xe0\xed@\xf0\xca\x14\xd0\x07\xcc\xdc\x0fo&\xfb\x13\x8eLa_\x80\xb7\xb7\xb4\xa0D\x9fF"
b"'N]\xb7\x81Cr\x0c\n\xb4\x8a\xf3\xecx\xf1\nC\x90\xc1\x9d \x0e>\x95_\xae\x8a\xd1dp\x9d\x10\xf2\xf1\x86\x06\xbe\xe0\xed@\xf0\xca\x14\xd0\x07\xcc\xdc\x0fo&\xfa\x13\x8eLa_\x80\xb7\xb7\xb4\xa0D\x9fF"
Taken 70199882 trials.
```
Xấp xỉ $2^{26}$ lần quay vòng nhân phẩm.

Debug với chờ kết quả mấy cái này làm mình nghĩ lại về việc làm về crypto...

# [Challenge 56: RC4 Single-Byte Biases](https://cryptopals.com/sets/6/challenges/56)

Bài này thực tế mình cũng có chạy song song hoá (chứ không thì bao giờ mới xong...) Nhưng mà, để cho đơn giản và dễ hiểu thì mình chỉ đưa code tuyến tính thôi.

Đầu tiên là xây dựng oracle:
```python
from Crypto.Cipher import ARC4
cookie = b64decode('QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F')
def oracle(msg: bytes):
    return ARC4.new(generate_key()).encrypt(msg + cookie)
```

Mỗi lần query oracle là chúng ta sẽ có một/hai ứng cử viên cho chữ cái ở một vị trí nào đó. Chúng ta lưu lại số lần mỗi ứng cử viên xuất hiện để sau chọn giá trị có tần suất cao nhất:
```python
msglen = len(oracle(b''))
choice = []
for i in range(msglen):
    row.append([0] * 256)
```

Và query $2^{32}$ lần tổng cộng:
```python
for padlen in range(32):
    for _ in range(2 ** 27):
        encrypted = oracle(b'A' * padlen)
        idx = 15 - padlen
        if 0 <= idx < msglen:
            choice[idx][encrypted[15] ^ 240] += 1
        idx = 31 - padlen
        if 0 <= idx < msglen:
            choice[idx][encrypted[31] ^ 224] += 1
```

Tái tạo chuỗi gốc và confirm thôi:
```python
bytes_ = []
for freq in choice:
    bytes_.append(freq.index(max(freq)))
assert cookie == bytes(bytes_)
```

**Easter egg:** Không liên quan đến Hip-Hop nữa, nhưng là một historical trivia khá hay. Các bạn có thể (bắt đầu) tìm hiểu thêm ở [link Wikipedia này](https://en.wikipedia.org/wiki/Secret_decoder_ring#Film_references).

***
**<div align="center">Hết rồi đó.</div>**
***