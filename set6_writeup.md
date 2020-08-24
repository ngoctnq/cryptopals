<sup>Đây là một bài trong series [Cùng giải Cryptopals!](https://viblo.asia/s/cung-giai-cryptopals-68Z00nw9ZkG).<br>Các bạn nên tự làm hoặc vừa đọc vừa làm thay vì đọc lời giải trực tiếp.</sup>
***
**<div align="center">Không chần chừ gì nữa, hãy bắt đầu nào!</div>**
***

# [Challenge 41: Implement unpadded message recovery oracle](https://cryptopals.com/sets/6/challenges/41)

Cho dù không được bảo mật lắm nhưng homomorphic (deterministic) encryption sẽ có lợi trong encrypted multiparty computation, nên các bạn đừng nghĩ là RSA vào sọt rác được rồi nhé :(
```python
N, e, d = generate_keys()
s = 42
# encrypt text
encrypted = RSA_encrypt(s, N, e)
# encrypt random
enc2 = RSA_encrypt(69, N, e)
# decrypt morphed
dec2 = RSA_encrypt((encrypted * enc2) % N, N, d)
# get original string
decrypted = (dec2 * invmod(69, N)) % N
assert s == decrypted
```

# [Challenge 42: Bleichenbacher's e=3 RSA Attack](https://cryptopals.com/sets/6/challenges/42)

Ở code hiện tại chúng ta bỏ qua phần ASN.1 và giả sử chuỗi đó dài 20 bytes (như SHA-1) — trong thực tế, độ dài của tin nhắn sẽ phụ thuộc vào nội dung của đoạn ASN.1. Bắt đầu bằng việc tạo RSA key, chúng ta để while loop để không ra key nào mà Euler's Phi chia hết cho 3:
```python
while True:
    try:
        N, e, d = generate_keys(public_exp=3, prime_bitlength=1024)
        break
    except AssertionError:
        continue
# size of modulus i.e. maxsize of message
max_size = N.bit_length() // 8
```

Hàm ký thông tin:
```python
def sign_msg(msg):
    assert len(msg) == 40
    padded = b'0001' + b'ff' * (max_size - 20 - 3) + b'00' + msg
    return RSA_encrypt(int.from_bytes(unhexlify(padded), 'big'), N, d)
```

Và hàm kiểm tra: đã cố tình chỉ đọc khoán 40 bytes và không kiểm tra xem nó có nằm cuối chuỗi không.
```python
def verify_msg(msg, cipher):
    assert len(msg) == 40
    res = hexlify(RSA_encrypt(cipher, N, e).to_bytes(max_size, 'big'))
    string = re.findall(rb'0001(?:ff)+00([0-9a-f]{40})', res)
    if len(string) == 0: return False
    return msg == string[0]
```

Test xem có hoạt động không (đương nhiên rồi).
```python
hashed = sha1(b'hi mom').encode()
signature = sign_msg(hashed)
assert verify_msg(hashed, signature)
```

Chúng ta phải tự viết hàm tìm căn bậc 3. Trong đó, mình có sử dụng geometric search để tìm giá trị nhỏ nhất sao cho khi lập phương lên sẽ lớn hơn giá trị decrypt mong muốn.
```python
def cube_root_ceil(i: int) -> int:
    step_size = 1
    greed = True
    root = 1
    while True:
        ok = root ** 3 - i > 0
        if ok:
            if step_size == 1:
                return root
            else:
                step_size //= 2
                root -= step_size
                greed = False
        else:
            root += step_size
            if greed:
                step_size *= 2
```

Và phá:
```python
# forging the signature
padded = b'0001ff00' + hashed + b'0' * (max_size * 2 - 40 - 8)
target = int.from_bytes(unhexlify(padded), 'big')
forged = cube_root_ceil(target)
assert verify_msg(hashed, forged)
```

Về lý thuyết thì chắc là tấn công này sẽ vẫn hoạt động với các exponent nhỏ như 5; tuy nhiên có lẽ nếu tính cả độ dài đoạn ASN.1 vào thì lượng degree of freedoms (`\x00` byte ở cuối) không đủ để chứa chênh lệch của hash được chấp nhận và ceiling của căn bậc 5 của nó mũ 5 lên lại.

# [Challenge 43: DSA key recovery from nonce](https://cryptopals.com/sets/6/challenges/43)

Bỏ qua phần parameter generation do yêu cầu giữa các số nguyên tố khá khó tìm, chúng ta implement toàn bộ phần còn lại của DSA theo [Wikipedia](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#Operation):
```python
def generate_keys() -> (int, int):
    privkey = randrange(1, q)
    pubkey = pow(g, privkey, p)
    return pubkey, privkey

def sign(msg: bytes, privkey: int) -> int:
    hashed = int.from_bytes(unhexlify(sha1(msg)), 'big')
    while True:
        k = randrange(1, q)
        r = pow(g, k, p) % q
        if r == 0: continue
        s = (invmod(k, q) * (hashed + privkey * r)) % q
        if s == 0: continue
        return r, s

def verify(msg: bytes, signature: (int, int), pubkey: int) -> bool:
    r, s = signature
    if not (0 < r < q and 0 < s < q): return False
    w = invmod(s, q)
    hashed = int.from_bytes(unhexlify(sha1(msg)), 'big')
    u1 = (hashed * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(pubkey, u2, p)) % p) % q
    return v == r
```

Đừng quên test xem code mình chạy không nhé.
```python
pubkey, privkey = generate_keys()
text = b'ngoctnq'
signature = sign(text, privkey)
assert verify(text, signature, pubkey)
```

Hàm khôi phục private key từ nonce khá dễ code:
```python
def privkey_from_subkey(msg: bytes, signature: (int, int), subkey: int) -> int:
    r, s = signature
    hashed = int.from_bytes(unhexlify(sha1(msg)), 'big')
    return ((s * subkey - hashed) * invmod(r, q)) % q
```

Như đã hướng dẫn ở trên, với search space bé (65537 trường hợp), chúng ta có thể bruteforce ra private key một cách dễ dàng.
```python
for k in trange(1, 2 ** 16 + 1):
    privkey = privkey_from_subkey(msg, (r, s), k)
    if pubkey == pow(g, privkey, p): break
# check hash integrity
assert sha1(hex(privkey)[2:].encode()) == '0954edd5e0afe5542a4adf012611a91912a3ec16'
# check for signature
hashed = int.from_bytes(unhexlify(sha1(msg)), 'big')
r_ = pow(g, k, p) % q
s_ = (invmod(k, q) * (hashed + privkey * r)) % q
assert (r_, s_) == (r, s)
```

*Chú ý:* Để ra được đúng hash trong đề bài, cần có `\n` ở cuối mỗi dòng (tổng cộng là 2 newlines).

**Easter egg:** Chỗ text được ký
> For those that envy a MC it can be hazardous to your health<br>
> So be friendly, a matter of life and death, just like a etch-a-sketch

là lời bài hát [Lyrics of Fury của Eric B. & Rakim](https://www.youtube.com/watch?v=GFOeJOtq_xc).

# [Challenge 44: DSA nonce recovery from repeated nonce](https://cryptopals.com/sets/6/challenges/44)

Nhìn công thức của $r$ chúng ta có:

$$
r = (g^k\mod p) \mod q
$$

không phụ thuộc vào gì ngoài $k$ ($p$, $q$, $g$ không đổi với mọi user), nên nếu $k$ trùng thì $r$ cũng sẽ giống nhau. Ngoài ra, công thức tìm private key trong đề bài có thể tìm ra từ công thức của $s$ (gợi ý: trừ 2 giá trị khác nhau của $s$ với cùng một $k$):

$$
s = k^{-1}(m+xr)\mod q.
$$

Và giờ thì code dễ rồi.
```python
pubkey = 0x...
lines = BytesIO(requests.get('https://cryptopals.com/static/challenge-data/44.txt').content)
msgs = []
rs = []
ss = []
ms = []
for _ in range(11):
    msgs.append(lines.readline().lstrip(b'msg: ').strip(b'\n'))
    ss.append(int(lines.readline().lstrip(b's:')))
    rs.append(int(lines.readline().lstrip(b'r:')))
    ms.append(int(lines.readline().lstrip(b'm:'), 16))
    assert verify(msgs[-1], (rs[-1], ss[-1]), pubkey)
# find which r is where
pos = dict()
for idx in range(11):
    r = rs[idx]
    if r not in pos:
        pos[r] = [idx]
    else:
        pos[r].append(idx)
        break
assert len(pos[r]) == 2, 'No reused k found!'
# get the nonce
pos1, pos2 = pos[r]
m1, m2 = ms[pos1], ms[pos2]
s1, s2 = ss[pos1], ss[pos2]
k = ((m1 - m2) % q * invmod((s1 - s2) % q, q)) % q
# get the private key
privkey = privkey_from_subkey(msgs[pos1], (r, s1), k)
assert pubkey == pow(g, privkey, p)
assert sha1(hex(privkey)[2:].encode()) == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'
```

**Easter egg:** Nội dung trong chỗ message đó
> Listen for me, you better listen for me now.<br>
> Listen for me, you better listen for me now.<br>
> When me rockin' the microphone me rock on steady,<br>
> Yes a Daddy me Snow me are de article dan.<br>
> But in a in an' a out de dance em<br>
> Aye say where you come from a,<br>
> People em say ya come from Jamaica,<br>
> But me born an' raised in the ghetto that I want yas to know,<br>
> Pure black people mon is all I mon know.<br>
> Yeah me shoes a an tear up an' now me toes is a show a<br>
> Where me a born in are de one Toronto, so

là lời bài hát [Informer của Snow](https://www.youtube.com/watch?v=TSffz_bl6zo) (nếu có sai gì thì đó là tại Jamaican English).

# [Challenge 45: DSA parameter tampering](https://cryptopals.com/sets/6/challenges/45)

Với generator $g=0\mod p$, chúng ta sẽ có public key $y=0$, nửa signature $r = 0$. Từ đây, ta có thể nhận ra rằng bất cứ bộ key nào, bất cứ chữ ký nào, ta có thể cho bừa một giá trị $s$ và hệ thống sẽ đều trả về OK, do mục so sánh cụ thể của verify chỉ so sánh $r$. Nếu bạn vẫn cảm thấy không an tâm, thì đây là kết quả cụ thể của $v$, cũng do $g=y=0$:

$$
v = g^{ms^{-1}}y^{rw}=0.
$$

Với generator $g=1\mod p$, cụ thể là với $g=p+1$: chúng ta sẽ có public key $y=1$, nửa signature $r=1$. Tương tự như trên, chúng ta có $v=r$ với mọi settings do $g=y=1$:

$$
v = g^{ms^{-1}}y^{rw}=1.
$$

**Chú ý:** Bài này lời giải của mình ngắn hơn rất nhiều so với hướng dẫn? Nên nếu mình có sai thì mọi người hãy chỉ ra nhé.

# [Challenge 46: RSA parity oracle](https://cryptopals.com/sets/6/challenges/46)

Câu này thực sự vừa khó hiểu vừa khó giải thích. Cơ mà dễ nhất là cứ viết code đề bài trước đã:
```python
n, e, d = generate_keys(prime_bitlength=1024)
def is_plaintext_even(cipher: int) -> bool:
    return bin(RSA_encrypt(cipher, n, d))[-1] == '0'
secret = b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
encrypted = RSA_encrypt(int.from_bytes(secret, 'big'), n, e)
```

Viết tạm một hàm biến đổi từ `int` sang `bytes` cho dễ sử dụng từ bây giờ trở đi:
```python
def int_to_bytes(s: int, bit_length=None) -> bytes:
    bit_length = bit_length or s.bit_length()
    return int.to_bytes(s, (bit_length + 7) // 8, 'big')
```

Và viết code đầu ra giống i xì như hướng dẫn của đề bài (trừ việc mình không in ra cụ thể, vì đoạn đầu rất nhiều rác):
```python
upper_bound = Fraction(n, 1)
lower_bound = Fraction(0, 1)
for i in range(n.bit_length()):
    i += 1
    encrypted = (encrypted * pow(2, e, n)) % n
    if is_plaintext_even(encrypted):
        upper_bound = (upper_bound + lower_bound) / 2
    else:
        lower_bound = (upper_bound + lower_bound) / 2

decrypted = int_to_bytes(int(upper_bound))
assert decrypted == secret
```

Tại sao phương pháp này hoạt động? Chúng ta có một fact sau:
> Sau khi đã nhân ciphertext với $2^e\mod n$ tất cả $k$ lần, tồn tại $p\in\mathbb{N}$ sao cho plaintext mới là $0<2^km-pN<N$, và từ đó chúng ta giới hạn được $\frac{p}{2^k}N < m < \frac{p+1}{2^k}N$.

Rất đơn giản và dễ hiểu, sau khi nhân plaintext với 2 nhiều lần, chúng ta sẽ có một số rất lớn, và $p$ chính là thương số nguyên khi chia plaintext lớn đó với modulus $N$, và $2^km-pN$ chính là số dư trong phép chia đó. Ở một bước $k$ bất kỳ, chúng ta có plaintext mới là $0<2^km-pN<N$. Từ đó chúng ta lại nhân 2 lên, và sử dụng bit cuối, chúng ta biết được nó có overflow không. Xảy ra 2 trường hợp:
- Nếu không overflow: plaintext mới sẽ là $0<2^{k+1}m-2pN<N$, tương đương với $\frac{p}{2^k}N < m < \frac{2p+1}{2^{k+1}}N$. Trong trường hợp đó, upper bound đã dịch về chính giữa lower bound cũ và upper bound cũ:

$$
\frac{1}{2}\left(\frac{p}{2^k}+\frac{p+1}{2^k}\right)=\frac{2p+1}{2^{k+1}}.
$$

- Nếu có overflow: chúng ta có $N<2^{k+1}m-2pN<2N$, nên giá trị mới sau khi lấy modulo $N$ là giá trị cũ nhân đôi trừ đi $N$. Từ đó ta có $0<2^{k+1}m-(2p+1)N<N$, tương đương với $\frac{2p+1}{2^{k+1}}N < m < \frac{p+1}{2^k}N$. Trong trường hợp đó, lower bound đã dịch về chính giữa upper bound cũ và lower bound cũ.

Từ đó suy ra ở mỗi bước thử ta có thể chia đôi khoảng cách giữa chặn trên và chặn dưới của tin nhắn, và vì ban đầu khoảng cách đó là $N-0=N$, sau $\log_2 N$ bước thì đương nhiên là khoảng cách đó sẽ về còn 1, nghĩa là ra đúng kết quả mong muốn.

**Easter egg:** Câu bí mật trong base64 đó là
> That's why I found you don't play around with the Funky Cold Medina

là lyrics trong bài [Funky Cold Medina của Tone-Loc](https://www.youtube.com/watch?v=63ZIf2H9S0E).

# [Challenge 47: Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)](https://cryptopals.com/sets/6/challenges/47)

Đầu tiên chúng ta implement hàm padding PKCS#1v1.5:
```python
def pkcs15_pad(s: bytes, length: int) -> bytes:
    randlen = length - 3 - len(s)
    assert randlen >= 0, "Message longer than targeted length."
    return b'\x00\x02' + bytes([randint(1, 255) for _ in range(randlen)]) + b'\x00' + s
```

Rồi tiếp đến là viết oracle:
```python
def verify_pkcs1_padding(cipher: int, n: int, d: int) -> bool:
        decrypted = int_to_bytes(RSA_encrypt(cipher, n, d), n.bit_length())
        return decrypted[0] == 0 and decrypted[1] == 2 # and b'\x00' in decrypted[2:]
```

Sau rất nhiều thời gian debug, đây là code BB'98:
```python
def bleichenbacher_cca_rsa_pkcs1(c: int,
                                 n: int,
                                 e: int,
                                 padding_oracle: Callable[[int], bool]
                                ) -> bytes:
    # skipping step 1 because cipher is already pkcs1.5-conforming
    i = 1
    Blog2 = (n.bit_length() - 9) // 8 * 8
    B = (1 << Blog2)
    M = [[2 * B, 3 * B - 1]]
    while True:
        # step 2a
        if i == 1:
            s = ceil(Fraction(n >> Blog2, 3))
            while True:
                if padding_oracle((c * pow(s, e, n)) % n):
                    break
                else:
                    s += 1
        # step 2b
        elif len(M) > 1:
            s += 1
            while True:
                if padding_oracle((c * pow(s, e, n)) % n):
                    break
                else:
                    s += 1
        # step 2c
        else:
            a, b = M[0]
            rn = ceil(Fraction(2 * (b * s - 2 * B), n)) * n
            lower = ceil(Fraction(2 * B + rn, b))
            upper = floor(Fraction(3 * B + rn, a))
            s = lower
            while True:
                if padding_oracle((c * pow(s, e, n)) % n):
                    break
                if s < upper:
                    s += 1
                else:
                    rn += n
                    lower = ceil(Fraction(2 * B + rn, b))
                    upper = floor(Fraction(3 * B + rn, a))
                    s = lower
        # step 3
        new_M = []
        for a, b in M:
            lower = a * s - 3 * B + 1
            upper = b * s - 2 * B
            rn = ceil(Fraction(lower, n)) * n
            while rn <= upper:
                new_pair = [max(a, ceil(Fraction(2 * B + rn, s))),
                            min(b, floor(Fraction(3 * B - 1 + rn, s)))]
                new_M.append(new_pair)
                rn += n
        M = new_M
        # step 4
        if len(M) == 1 and M[0][0] == M[0][1]:
            return M[0][0]
        else: i += 1
```

Có vài điểm cần lưu ý trong code này:
- Đầu tiên là rounding error xảy ra thường xuyên như cơm bữa, và nếu bạn dùng `/` thay vì `Fraction` (hoặc high-precision `decimal`), thì đảm bảo code bạn toang. Mình đã mất bao lâu so sánh paper và code để rồi nhận ra là mình dính rounding error.
- Trong paper ở bước 3 bạn phải lấy union các subintervals; nghĩa là, nếu trong quá trình thử các $a,b,r$ xảy ra các subintervals chồng lên nhau (ví dụ, có 2 intervals là $[0,2]$ và $[1,3]$), thì chúng ta phải merge chúng với nhau (ví dụ, thành $[0,3]$). Tuy nhiên, trong lúc code mình có để một test (`assert`) vào, và trường hợp này rất may mắn không xảy ra. Chắc là có lý thuyết giải thích, nhưng mình đang chưa chứng minh được — có gì mọi người bàn luận nhé.

Viết sẵn luôn đoạn code verify, vừa dùng bài này tẹo xài lại bài 48 nữa:
```python
def chall47_48(msg: bytes, modulus_bitsize: int):
    n, e, d = generate_keys(prime_bitlength=modulus_bitsize//2)
    m = pkcs15_pad(msg, modulus_bitsize//8)
    c = RSA_encrypt(int.from_bytes(m, 'big'), n, e)
    padding_oracle = lambda x: verify_pkcs1_padding(x, n, d)
    decrypted = int_to_bytes(bleichenbacher_cca_rsa_pkcs1(c, n, e, padding_oracle), modulus_bitsize)
    assert decrypted == m
```

Và chạy xem có lỗi gì không (đương nhiên là rát nhiều bug rồi, sửa hết mất 1 ngày đó).
```python
chall47_48(b'kick it, CC', 256)
```

**Easter egg:** "Kick it, C.C." là lời một bài hát nào đấy của nhóm nhạc rock Poison hay sao ấy? Trước đoạn guitar solo của C.C. DeVille thì Bret Michaels hay hú lên một câu kiểu đó.

# [Challenge 48: Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)](https://cryptopals.com/sets/6/challenges/48)

Bao nhiêu code cần thiết viết xong cả rồi, thì chỉ việc giải thôi:
```python
chall47_48(b'kick it, CC', 768)
```

Nếu các bạn để ý, code oracle hiện tại (như đề bài yêu cầu) đang "lỏng" hơn rất nhiều so với yêu cầu thực tế trong FIPS:
- Không giới hạn dưới số bytes padding
- Không kiểm tra có byte `\x00` cuối padding

Nhờ vậy mà code chạy ra nhanh hơn rất nhiều, mà kết quả vẫn đúng. Trong thực tế thì nhớ implement thêm 2 mục kia nhé.

***
**<div align="center">Hết rồi đó.</div>**
***