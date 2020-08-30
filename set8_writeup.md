<sup>Đây là một bài trong series [Cùng giải Cryptopals!](https://viblo.asia/s/cung-giai-cryptopals-68Z00nw9ZkG).<br>Các bạn nên tự làm hoặc vừa đọc vừa làm thay vì đọc lời giải trực tiếp.</sup>
***
<div align="center">Set này hiện tại không được publish trên trang chủ,<br>
và email thì cũng đến mùa quýt mới được trả lời,<br>
    nên mình đã Google đề để làm  (｡・ ω<)ゞ</div>
    
**<div align="center">Cẩn thận nhé, phần này rất rất dài, và khó hơn các phần trước rất nhiều.</div>**
***

# [Challenge 57: Diffie-Hellman Revisited: Small Subgroup Confinement](https://toadstyle.org/cryptopals/57.txt)

Tạo hàm sinh ra MAC đã.
```python
enclen = (p.bit_length() + 7) // 8
msg = b"crazy flamboyant for the rap enjoyment"
def get_mac(key: int, msg: bytes) -> bytes:
    return digest(key.to_bytes(enclen, 'big'), msg, 'md5')
```

Sử dụng [factordb](factordb.com), chúng ta có các ước của $j$ (có multiplicity 1) bé hơn $2^{16}$:
```python
factors = [2, 5, 109, 7963, 8539, 20641, 38833, 39341, 46337, 51977, 54319, 57529]
```

Do chỉ cần các ước số có tích vừa đủ lớn hơn $q$ để sử dụng định lý thặng dư Trung Hoa, chúng ta lọc bớt mấy số to to đi và tính luôn tích đó:
```python
# keep only factors that sum up to be greater than q
prod = 1
for i, v in enumerate(factors):
    prod *= v
    if prod > q: break
assert prod > q
del factors[i + 1:]
```

Tạo secret key của Bob mà Eve (chúng ta) cần phải lấy được:
```python
# bob's secret key
secret = randrange(1, q)
```

Với mỗi một ước số trong `factors`, chúng ta lấy MAC (bất hợp lệ) của Bob, rồi bruteforce ra số dư khi chia private exponent của Bob với ước số đó:
```python
# remainder modulus `factors`
remainders = []
for factor in factors:
    # get element of order `factor`
    exponent = (p - 1) // factor
    while True:
        h = randrange(1, p)
        h = pow(h, exponent, p)
        if h != 1: break
    # get message encrypted with invalid public key
    mac = get_mac(pow(h, secret, p), msg)
    # bruteforce remainders
    for i in range(factor):
        if mac == get_mac(pow(h, i, p), msg):
            remainders.append(i)
            break
assert len(factors) == len(remainders)
```

Và sử dụng định lý thặng dư Trung Hoa để lấy được secret key của Bob:
```python
# do chinese remainder theorem
recovered = 0
for factor, remainder in zip(factors, remainders):
    factor_ = prod // factor
    inverse = invmod(factor_, factor)
    recovered = (recovered + remainder * inverse * factor_) % prod

assert recovered == secret
```

**Easter egg:** Tin nhắn được MAC
> crazy flamboyant for the rap enjoyment

là lyrics từ bài [Protect Ya Neck của Wu-Tang Clan](https://www.youtube.com/watch?v=ZrQ0VMHK0Ec). Đây cũng là title của email cần gửi đến Cryptopals để lấy đề set 8 này.

# [Challenge 58: Pollard's Method for Catching Kangaroos](https://toadstyle.org/cryptopals/58.txt)

Chúng ta implement đúng như hướng dẫn đề bài:
```python
def pollard(y, min_exp, max_exp, k=16, p=p, q=q, g=g):
    # generate params from k
    f = lambda y: 2 ** (y % k)
    '''
    avg of f is (2 ^ k - 1) / k
    multiplied by 4 -> (2 ^ (k+2) - 4) / k
    '''
    N = (2 ** (k + 2)) // k

    # get the endpoint
    xT = 0
    yT = pow(g, max_exp, p)
    for _ in range(N):
        fT = f(yT)
        xT += fT
        yT = (yT * pow(g, fT, p)) % p

    # then search if we met
    xW = 0
    yW = y
    while xW < max_exp - min_exp + xT:
        fW = f(yW)
        xW += fW
        yW = (yW * pow(g, fW, p)) % p

        if yW == yT:
            return max_exp + xT - xW
```

Và chạy 2 tests:
```python
y = 7760073848032689...
res = pollard(y, 0, 2 ** 20)
assert pow(g, res, p) == y
print(res) # 705485

y = 9388897478013399...
res = pollard(y, 0, 2 ** 40, k=20)
assert pow(g, res, p) == y
print(res) # 359579674340
```

Chú ý để $k$ cao lên để kangaroo nhảy được xa hơn. Với $k=16$, ước tính loop sau mất tầm 30' trường hợp xấu nhất; với $k=20$, 3 phút (thực tế mất 2'), và với $k=25$, 1' (nhưng loop đầu đã mất 2 phút). Cụ thể, do với $k$ lớn, bước nhảy xa hơn, và do số bước trước đặt trap $N$ là trung bình của độ dài các bước nhảy, loop đầu sẽ lâu hơn với $k$ lớn hơn. Tuy nhiên, vì bước nhảy dài hơn, nên thỏ con sẽ nhảy qua từ lower bound đến upper bound rất nhanh để mau chóng rơi vào trap chúng ta đã đặt. Vì vậy, nếu bound cho exponent lớn, hãy đặt $k$ cao lên, vì độ dài loop 2 sẽ bé đi rất rất rất nhiều so với lượng thời gian tăng lên để chạy loop 1; và giảm $k$ trong trường hợp ngược lại.

Ở phần 2, chúng ta copy i xì code của bài trước. Trong đó, các ước bé hơn $2^{16}$ của $j$ là:
```python
factors = [2, 12457, 14741, 18061, 31193, 33941, 63803]
prod = 2 * 12457 * 14741 * 18061 * 31193 * 33941 * 63803
```

Lần này chúng ta sẽ cần dùng đến public key của Bob:
```python
# bob's key
secret = randrange(1, q)
public = pow(g, secret, p)
```

Dùng code của bài trước chúng ta sẽ có được số dư `residue` khi chia `secret` cho `prod`. Sử dụng Pollard's Method như bài trước và thế là hết:
```python
# y = g^x = g^(n + mr) = g^n + (g^r)^m
for k in range(25, 0, -1):
    m = pollard(
        (public * pow(g, q - residue, p)) % p,
        0,
        q // prod + 1,
        k = k,
        g = pow(g, prod, p)
    )
    if m is not None: break
recovered = prod * m + residue
assert recovered == secret
```

Nên nhớ rằng, Pollard's Method là probabilistic, nó không chắc chắn sẽ đưa ra đáp án. Trong trường hợp đó, hãy đổi $k$ xem có giải ra được không nhé.

# [Challenge 59: Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks](https://toadstyle.org/cryptopals/59.txt)

Việc đầu tiên cần làm là implement thuật toán Elliptic Curve, bắt đầu từ `WeierstrassCurve`:
```python
class WeierstrassCurve:
    def __init__(self, a, b, p, g, q, order):
        '''
        @a, b   params of the curve equation
                    y^2 = x^3 + ax + b
        @p      the GF(p) to work on
        @g      the coordinates of the generator
        @q      the order of the generator
        @order  the number of elements in the finite field
                    generated by the curve on GF(p)
        '''
        self.a = a
        self.b = b
        self.p = p
        self.q = q
        self.order = order
        self.g = self.point(*g)
        self.id = self.point(0, 1)

        assert self.g * q == self.id
    
    def point(self, x, y):
        return WeierstrassPoint(self, x, y)

    def __eq__(self, obj):
        # same config different object is different field
        # this is to prevent recursive comparison
        return id(self) == id(obj)

    def get_eqn(self):
        ret = 'x^3'
        if self.a > 0:
            ret += f' + {self.a}x'
        elif self.a < 0:
            ret += f' - {-self.a}x'
        if self.b > 0:
            ret += f' + {self.b}'
        elif self.b < 0:
            ret += f' - {-self.b}'
        return ret

    def generate_keypair(self):
        private = randrange(0, self.q)
        public = self.g * private
        return private, public
```

Và class cho một điểm bất kỳ trên curve đó. Chú ý, disable cái assertion về điểm nằm trong curve, và dòng tối ưu nhân điểm, để attack này hoạt động.
```python
class WeierstrassPoint:
    def __init__(self, field, x, y):
        self.field = field
        self.x = x
        self.y = y

        # make sure the point is valid -- disable this for the attack
        # if x != 0 or y != 1:
        #     assert (pow(x, 3, curve.p) + curve.a * x + curve.b) % curve.p == pow(y, 2, curve.p), "Point not on the curve!"


    def __str__(self):
        return f'{(self.x, self.y) if self != self.field.id else "Identity"}' + \
               f' of {self.field.get_eqn()}'
    
    __repr__ = __str__

    def copy(self):
        # shallow copy
        return WeierstrassPoint(self.field, self.x, self.y)

    def __neg__(self):
        return WeierstrassPoint(self.field, self.x, self.field.p - self.y)

    def __eq__(self, obj):
        return self.field == obj.field and self.x == obj.x and self.y == obj.y

    def __add__(self, obj):
        assert isinstance(self, WeierstrassPoint) and isinstance(obj, WeierstrassPoint), \
                'Can only add Point with another Point.'
        assert self.field == obj.field, 'Points must be of the same field.'
        
        field = self.field
        if self == field.id:
            return obj
        if obj == field.id:
            return self
        if self == -obj:
            return field.id

        if self == obj:
            m = ((3 * self.x * self.x + field.a) * invmod(2 * self.y, field.p)) % field.p
        else:
            m = ((obj.y - self.y) * invmod(obj.x - self.x, field.p)) % field.p
        
        new_x = (m * m - self.x - obj.x) % field.p
        new_y = (m * (self.x - new_x) - self.y) % field.p
        
        return WeierstrassPoint(field, new_x, new_y)

    def __mul__(self, scalar):
        assert isinstance(self, WeierstrassPoint) and isinstance(scalar, int), \
                'Can only multiply Point with a scalar.'
        # disable this for the attack
        # scalar %= self.field.q
        pow2 = self
        acc = self.field.id
        while True:
            if scalar & 1:
                acc += pow2
            scalar >>= 1
            if scalar == 0: return acc
            pow2 += pow2
    
    def __rmul__(self, scalar):
       return self * scalar
```

Implement hàm lấy [Jacobi symbol](https://en.wikipedia.org/wiki/Jacobi_symbol) vì sau này sẽ cần dùng:
```python
def jacobi_symbol(n: int, p: int):
    assert n > 0 and p > 0, 'Parameters to Jacobi symbol must be positive!'
    assert p % 2, 'p must be odd.'
    sign = 1
    while True:
        if p == 1: return sign
        n %= p
        if n == 0: return 0
        even_invert = (p % 8) in (3, 5)
        while n & 1 == 0:
            if even_invert:
                sign = -sign
            n >>= 1
        if n == 1: return sign
        if n % 4 == 3 and p % 4 == 3:
            sign = -sign
        n, p = p, n
```

Implement luôn hàm căn bậc 2 theo modulo ([thuật toán Tonelli-Shanks](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm)):
```python
def sqrtmod(n: int, p: int) -> int:
    ''' Tonelli-Shanks algorithm '''
    # find q, s such that q2^s = p-1
    q = p-1
    s = 0
    while q & 1 == 0:
        s += 1
        q >>= 1
    # get a quadratic non-residue
    for z in range(1, p):
        if jacobi_symbol(z, p) == -1:
            break
    # let
    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) >> 1, p)
    # loop
    while True:
        if t == 0: return 0
        if t == 1: return r
        t2i = t
        for i in range(1, m):
            t2i = pow(t2i, 2, p)
            if t2i == 1: break
        else:
            return None
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = (t * c) % p
        r = (r * b) % p
```

Test handshake giữa Alice và Bob:
```python
curve = WeierstrassCurve(
    a = -95051,
    b = 11279326,
    p = 233970423115425145524320034830162017933,
    g = (182, 85518893674295321206118380980485522083),
    q = 29246302889428143187362802287225875743,
    order = (29246302889428143187362802287225875743 << 3)
)
# test handshake
priv_a, pub_a = field.generate_keypair()
priv_b, pub_b = field.generate_keypair()
assert pub_a * priv_b == pub_b * priv_a
```

Tạo hàm ký với key chung lấy được từ Diffie-Hellman:
```python
# according to ECIES, x coord is enough (uh, no?)
# since y can be computed from x *without* the sign, we add that too
msg = b"crazy flamboyant for the rap enjoyment"
def get_mac(pubkey: Point) -> bytes:
    return digest(int_to_bytes(pubkey.x, curve.p.bit_length()) + \
        (b'+' if pubkey.y * 2 < curve.p else b'-'), msg, 'md5')
```

Trong tiêu chuẩn [ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme#Encryption), họ chỉ dùng toạ độ $x$ trong public key để ký. Tuy nhiên, với mỗi một giá trị $x$ tồn tại 2 giá trị $y$, nên trong KDF của chúng ta dùng cả 2: $x$ và dấu của $y$.

Tạo hàm generate một điểm có order $r$ trên curve tương tự với RSA:
```python
def generate_point(curve, a, b, q, r):
    # generate new point of order r without randomness
    point = curve.id.copy()
    for x in range(curve.p):
        y = sqrtmod((pow(x, 3, curve.p) + a * x + b) % curve.p, curve.p)
        if y is None: continue
        # craft the point to override the error check
        point.x, point.y = x, y
        point *= (q // r)
        assert point * r == curve.id
        if point != curve.id: return point
```

Lần lượt tạo các điểm trên 3 curve fake kia để lấy các số dư như challenge 57. Trong đó, các ước nguyên tố đã được lọc sao cho chỉ giữ các số nguyên tố khác nhau và nhỏ nhất sao cho tích của chúng vẫn lớn hơn order của generator.
```python
# y^2 = x^3 - 95051*x + 210     233970423115425145550826547352470124412
a, b1, q1 = -95051, 210, 233970423115425145550826547352470124412
factors1 = [3, 11, 23, 31, 89, 4999, 28411]
remainders1 = []
for factor in factors1:
    point = generate_point(curve, a, b1, q1, factor)
    mac = get_mac(point * priv_a)
    for r in range(factor):
        if mac == get_mac(point * r):
            remainders1.append(r)
            break

# y^2 = x^3 - 95051*x + 504     233970423115425145544350131142039591210
b2, q2 = 504, 233970423115425145544350131142039591210
factors2 = [5, 7, 61, 12157]
remainders2 = []
for factor in factors2:
    point = generate_point(curve, a, b2, q2, factor)
    mac = get_mac(point * priv_a)
    for r in range(factor):
        if mac == get_mac(point * r):
            remainders2.append(r)
            break

# y^2 = x^3 - 95051*x + 727     233970423115425145545378039958152057148
b3, q3 = 727, 233970423115425145545378039958152057148
factors3 = [37, 67, 607, 1979, 13327, 13799]
remainders3 = []
for factor in factors3:
    point = generate_point(curve, a, b3, q3, factor)
    mac = get_mac(point * priv_a)
    for r in range(factor):
        if mac == get_mac(point * r):
            remainders3.append(r)
            break
```

Và lấy lại private key thôi:
```python
recovered, modulus = chinese_remainder(
    factors1 + factors2 + factors3,
    remainders1 + remainders2 + remainders3
)

assert modulus >= curve.q
assert recovered == priv_a
```

# [Challenge 60: Single-Coordinate Ladders and Insecure Twists](https://toadstyle.org/cryptopals/60.txt)

Viết code (hay chính xác là sửa pseudocode trong đề) tính scale theo ladder:
```python
def ladder(u: int, k: int, a: int, p: int) -> int:
    # calculate u * k, with u being the first coordinate and k a scalar
    u2, w2 = 1, 0
    u3, w3 = u, 1
    for i in reversed(range(p.bit_length())):
        b = 1 & (k >> i)
        if b: u2, u3, w2, w3 = u3, u2, w3, w2

        # don't compute this twice in the second line below
        u2u2, u2w2, w2w2 = u2 * u2, u2 * w2, w2 * w2
        u3, w3 = pow(u2 * u3 - w2 * w3, 2, p), (u * (u2 * w3 - w2 * u3) ** 2) % p
        u2, w2 = pow(u2u2 - w2w2, 2, p), (4 * u2w2 * (u2u2 + a * u2w2 + w2w2)) % p

        if b: u2, u3, w2, w3 = u3, u2, w3, w2
        
    return (u2 * invmod_prime(w2, p)) % p
```

Có lẽ việc sử dụng single-coordinate ladder chính là lý do tại sao trong ECIES chỉ sử dụng toạ độ $x$ thay vì cả 2.

Công thức của ladder thực ra nhìn thế thôi nhưng đa phần là hù doạ: trong 2 phép tính lại toạ độ thì phép tính đầu tiên là cộng 2 điểm $(u_2, w_2) + (u_3, w_3)$, và phép thứ 2 là nhân đôi một điểm $(u_2, w_2) + (u_2, w_2) = (u_2, w_2) * 2$. Hai công thức của 2 phép tính trên thì lằng nhằng thật và bạn không cần hiểu mà chỉ cần lấy từ EFD, còn phần lõi của Montgomery ladder thì đơn giản hơn rất nhiều: ở iteration thứ $i$, bạn sẽ có $(u_2, w_2)$ là giá trị sau khi đã nhân đến $k % (2^i)$, và $(u_3, w_3)$ là giá trị đó nhân với $k % (2^i) + 1$. Chứng minh bằng quy nạp sẽ cho ta thấy sau khi qua đủ số-bit-của-k iteration thì chúng ta sẽ có được kết quả đúng.

Đề bài muốn chúng ta map $u^2 = u^3 + 534u^2 + u$ với $u = x-178$. Thay thế vào công thức chính, ta có:

$$
\begin{aligned}
y^2 &= (x-178)^3 + 534(x-178)^2 + (x-178) \\
&= x^3 - 534x^2 + 95052x - 5639752 + 534x^2 - 190104x + 16919256 + x - 178 \\
&= x^3 - 95051x + 11279326
\end{aligned}
$$

Đây chính là Weierstrass Curve từ challenge trước.

Check kèo implementation của ladder:
```python
p = 233970423115425145524320034830162017933
q = 29246302889428143187362802287225875743
a = 534 # b = 1
assert ladder(4, q, a, p) == 0
```

Và thử như đề bài sẽ có:
```python
u = 76600469441198017145391791613091732004
v = (u * u * u + a * u * u + u) % p
print(ladder(u, 11, a, p)) # 0
print(jacobi_symbol(v, p)) # -1
```

Giá trị Jacobi symbol $-1$ có nghĩa là không tồn tại căn bậc 2 modulo $p$ của $v$.

Tương tự như challenge trước, chúng ta viết hàm tạo điểm trên curve:
```python
def generate_point(a, p, q, r):
    # generate new point of order r
    for u in range(1, p):
        v2 = (u * u * u + a * u * u + u) % p
        # make sure it's on the twist
        y = jacobi_symbol(v2, p)
        assert y != 0
        if y == 1:
            continue
        # craft the point to override the error check
        point = ladder(u, q // r, a, p)
        if point == 0: continue
        assert ladder(point, r, a, p) == 0
        return point
```

Và lần này thì hàm ký không cần giá trị toạ độ kia nữa:
```python
def get_mac(pubkey: int) -> bytes:
    return digest(
        int_to_bytes(pubkey),
        b"crazy flamboyant for the rap enjoyment",
        'md5'
    )
```

Tạo ECC keys cho Bob:
```python
secret = randrange(1, curve.q)
public = _ladder(4, secret, curve.a, curve.p)
```

Tương tự như challenge trên, chúng ta viết code sinh ra một điểm sao cho có một order $q$ cụ thể: nhớ rằng, nếu Jacobi symbol là $-1$, điều đó nghĩa là giá trị đó không phải là một số chính phương, và điểm đó không tồn tại trên curve mà nằm trên twist.
```python
def generate_point(a, p, q, r):
    # generate new point of order r with custom group order q
    for u in range(1, p):
        v2 = (u * u * u + a * u * u + u) % p
        # make sure it's on the twist
        y = jacobi_symbol(v2, p)
        assert y != 0
        if y == 1:
            continue
        # craft the point to override the error check
        point = _ladder(u, q // r, a, p)
        if point == 0: continue
        assert _ladder(point, r, a, p) == 0
        return point
```

Tìm ra order của twist và tìm các ước của chúng:
```python
q_ = 2 * curve.p + 2 - curve.order
factors = [11, 107, 197, 1621, 105143, 405373, 2323367]#, 1571528514013]
```

Chúng ta bỏ nghiệm cuối do nó quá lớn và sẽ mất 110 ngày (!) chỉ để tìm số dư khi chia cho nó. Giờ là code để tìm các số dư đó, có hỗ trợ thanh progress bar và xử lý đa luồng (vì code này mà để đơn luồng lâu kinh khủng):

```python
retval = Value('i', -1)
def find_remainders(u, ranger, mac):
    global retval
    for remainder in ranger:
        with retval.get_lock():
            if retval.value != -1:
                break
        mac_ = get_mac(_ladder(u, remainder, curve.a, curve.p))
        if mac == mac_:
            with retval.get_lock():
                retval.value = remainder
            break

def load_divider(u, f, mac):
    count = cpu_count()
    pool = Pool(count)
    retval.value = -1
    params = []
    step = f // count + int((f % count) > 0)
    bottom = 0
    for _ in range(count):
        params.append(range(bottom, min(bottom + step, f)))
        bottom += step

    pool.starmap(find_remainders, zip(repeat(u), params, repeat(mac)))
    return sorted([retval.value, f - retval.value])
```

Và tìm lấy số dư cuối cùng:
```python
print('Getting individual factors...')
for f in tqdm(factors):
    u = generate_point(curve.a, curve.p, q_, f)
    mac = get_mac(_ladder(u, secret, curve.a, curve.p))
    remainders.append(load_divider(u, f, mac))
    
print('Getting union factors...')
while len(factors) > 1:
    new_factors = []
    new_remainders = []
    len_factors = len(factors)
    midpoint = len_factors // 2 + len_factors % 2
    for idx1 in range(midpoint):
        idx2 = len_factors - idx1 - 1
        if idx1 == idx2:
            new_factors.append(factors[idx1])
            new_remainders.append(remainders[idx2])
            continue
        f1 = factors[idx1]
        f2 = factors[idx2]
        f3 = f1 * f2
        u3 = generate_point(curve.a, curve.p, q_, f3)
        mac = get_mac(_ladder(u3, secret, curve.a, curve.p))
        r3s = []
        for r1 in remainders[idx1]:
            for r2 in remainders[idx2]:
                r3, _ = chinese_remainder([f1, f2], [r1, r2])
                mac_ = get_mac(_ladder(u3, r3, curve.a, curve.p))
                if mac == mac_:
                    r3s.append(r3)
        new_factors.append(f3)
        new_remainders.append(r3s)
    
    factors = []
    remainders = []
    for f, r in sorted(zip(new_factors, new_remainders)):
        factors.append(f)
        remainders.append(r)

factor = factors[0]
remainders = remainders[0]
```

Trong đề bài có nhắc tới việc sẽ có 2 giá trị dư có thể xảy ra cho mỗi modulus, và lượng số dư có thể cho factor cuối sẽ là $2^7=128$. Con số này rất lớn, vì (*spoiler alert*) code chạy phần đằng sau mất tầm 6 tiếng cho mỗi khả năng trên. Vì vậy, chúng ta có thể sinh ra tất cả các khả năng trước, rồi sinh ra MAC như với mỗi ước riêng kia, để check xem số dư đó có thoả mãn không. Kết quả cuối cùng là bạn sẽ rút ra chỉ có 2 số dư tiềm năng thôi.

Do Pollard's Kangaroo yêu cầu phải có cả phép cộng và nhân, sử dụng mỗi Montgomery ladder không thôi sẽ không thành. Vì thế, có 2 việc chúng ta phải làm: 1 là tạo ra các candidate cho public key để xử lý:
```python
y = sqrtmod((public ** 3 + curve.a * public ** 2 + public) % curve.p, curve.p)
public = curve.point(public, y)
```

Khả năng thứ 2 của public key chính là `-public`, với giá trị toạ độ $y$ bị đổi dấu. Việc thứ 2 phải làm là implement thêm hàm cộng/nhân bình thường:
```python
def _add(self, obj):
    curve, x1, y1, x2, y2 = self.curve, self.x, self.y, obj.x, obj.y
    a, b, p = curve.a, curve.b, curve.p
    x3 = b * pow(y2 - y1, 2, p) * pow(x2 - x1, p - 1 - 2, p) - a - x1 - x2
    y3 = (2 * x1 + x2 + a) * (y2 - y1) * invmod_prime(x2 - x1, p) - b * pow(y2 - y1, 3, p) * pow(x2 - x1, p - 1 - 3, p) - y1
    return MontgomeryPoint(curve, x3 % p, y3 % p)

def _double(self):
    curve, x, y = self.curve, self.x, self.y
    a, b, p = curve.a, curve.b, curve.p
    x3 = b * pow(3 * x * x + 2 * a * x + 1, 2, p) * pow(2 * b * y, p - 1 - 2, p) - a - x - x
    y3 = (2 * x + x + a) * (3 * x * x + 2 * a * x + 1) * invmod_prime(2 * b * y, p) - b * pow(3 * x * x + 2 * a * x + 1, 3, p) * pow(2 * b * y, p - 1 - 3, p) - y
    return MontgomeryPoint(curve, x3 % p, y3 % p)
```

Cấu trúc của class `MontgomeryPoint` tương tự với lớp `WeierstrassPoint` ở bài trước; nếu có thắc mắc gì bạn có thể đọc code cụ thể tại [repo](https://github.com/ngoctnq/cryptopals) mình.

Sửa hàm Pollard's Kangaroo cho Elliptic Curve:
```python
def pollard(y, min_exp, max_exp, g, k=24, progress=True):
    # generate params from k
    f = lambda y: 2 ** (y.x % k)
    '''
    avg of f is (2 ^ k - 1) / k
    multiplied by 4 -> (2 ^ (k+2) - 4) / k
    '''
    N = (2 ** (k + 2)) // k

    assert y.curve == g.curve

    # get the endpoint
    xT = 0
    yT = g * max_exp
    if progress:
        ranger = trange(N)
    else:
        ranger = range(N)
    for _ in ranger:
        fT = f(yT)
        xT += fT
        yT += g * fT

    # then search if we met
    xW = 0
    yW = y
    if progress:
        pbar = tqdm(total=max_exp - min_exp + xT)
    while xW < max_exp - min_exp + xT:
        fW = f(yW)
        xW += fW
        yW += g * fW

        if progress:
            pbar.update(fW)

        if yW == yT:
            return max_exp + xT - xW
```

Và vì code này chạy rõ lâu, mà có nhiều khả năng phải thử ($4 = 2$ số dư $\times 2$ public keys), nên chúng ta lại chạy song song:
```python
# y = g^x = g^(r + qf) = g^r + (g^f)^q
def pollard_helper(public, r, progress=True):
    y = public - curve.g * r
    max_ = curve.q // factor
    q = pollard(y, 0, max_, y.curve.g * factor, 23, progress)
    if q is None: return
    ret = (q * factor + r) % curve.q
    return ret

# parallel compute all 4 instances
pool = Pool(cpu_count())
results = pool.starmap(pollard_helper,
    ((public, remainders[0], True),
    (-public, remainders[0], False),
    (public, remainders[1], False),
    (-public, remainders[1], False))
```

Và sau 6 tiếng chạy code chúng ta sẽ có kết quả:
```python
assert secret in results
for result in results:
    assert result is None or result == secret
```

**Ngoài lề:** Có một điều khá thú vị mà mình phát hiện ra: sau khi scale quá order của group thì các lý thuyết bay qua cửa sổ: khi scale với bội số của origin sẽ không về được origin nữa. Chắc là tại khi gặp origin 1 lần thì nó toang, vì origin là một điểm nằm ở vô cực, và $x/w$ chỉ là một ước lượng. Ngoài ra cũng tại điểm 0 và điểm origin đều cùng giá trị 0. Vấn đề này là một phần nhỏ của việc chỉ sử dụng toạ độ $x$, là mỗi giá trị của $x$ tương ứng với 2 điểm trên curve. Điều này cũng làm cho việc hàm fast multiplication (nhân đôi rồi cộng gộp) sẽ bị toang, do không biết được chính xác hiệu của 2 điểm đó; và chúng ta cần hiệu vì curve này không có công thức closed form cho cộng điểm, mà phải sử dụng differential addition.

# [Challenge 61: Duplicate-Signature Key Selection in ECDSA (and RSA)](https://toadstyle.org/cryptopals/61.txt)

### Phần 1: ECDSA

Đầu tiên chúng ta implement lại hàm ký và verify cho ECDSA:
```python
def sign(message, private_key, curve, hash_fn=sha256):
    q = curve.q

    # get the leftmost bits equal to the group order
    hashed = int.from_bytes(hash_fn(message).digest(), 'big')
    hashed >>= max(hashed.bit_length() - q.bit_length(), 0)

    # generate nonce key
    while True:
        private, public = curve.generate_keypair()
        k, r = private, public.x
        if r % q == 0: continue
        s = ((hashed + private_key * r) * invmod_prime(k, q)) % q
        if s != 0: break
        
    return r, s

def verify(message, signature, public_key, hash_fn=sha256):
    r, s = signature
    q = public_key.curve.q

    # get the leftmost bits equal to the group order
    hashed = int.from_bytes(hash_fn(message).digest(), 'big')
    hashed >>= max(hashed.bit_length() - q.bit_length(), 0)
    
    s_inv = invmod_prime(s, q)
    u1 = (hashed * s_inv) % q
    u2 = (r * s_inv) % q
    R = u1 * public_key.curve.g + u2 * public_key
    return r == R.x
```

Tạo chữ ký cho một random key:
```python
curve = WeierstrassCurve(
    a = -95051,
    b = 11279326,
    p = 233970423115425145524320034830162017933,
    g = (182, 85518893674295321206118380980485522083),
    q = 29246302889428143187362802287225875743,
    order = (29246302889428143187362802287225875743 << 3)
)
private, public = curve.generate_keypair()

message = b"leavin' is the hardest thing to do"
signature = sign(message, private, curve)
assert verify(message, signature, public)
```

Và tạo ra một đôi key mới có thể mạo danh chữ ký trên:
```python
# from the verify code
r, s = signature
q = curve.q
hashed = int.from_bytes(sha256(message).digest(), 'big')
hashed >>= max(hashed.bit_length() - q.bit_length(), 0)
s_inv = invmod_prime(s, q)
u1 = (hashed * s_inv) % q
u2 = (r * s_inv) % q
# craft public key
d_ = randrange(1, q)
t = (u1 + u2 * d_) % q
R = u1 * curve.g + u2 * public
g_ = invmod(t, q) * R
Q_ = d_ * g_
Q_.curve = WeierstrassCurve(
    a = -95051,
    b = 11279326,
    p = 233970423115425145524320034830162017933,
    g = (g_.x, g_.y),
    q = 29246302889428143187362802287225875743,
    order = (29246302889428143187362802287225875743 << 3)
)
assert verify(message, signature, Q_)
```

Thực ra tán công này khá đơn giản nếu bạn để ý một chút: chúng ta chọn generator và public key mới sao cho $R$ cũ và mới giống nhau:

$$
R' = (u_1 + u_2d') * G' = (u_1 + u_2d') * (u_1 + u_2d')^{-1} * R = R.
$$

Điều quan trọng cần nhớ ở đây là với các thông tin có được từ chủ nhân chính thống, chúng ta có được key trộn cần mạo danh, và tìm một đôi $(d',G')$ để cho giá trị đó không đổi không quá khó. Đặc biệt là với order của generator là nguyên tố, tất cả các giá trị mà generator đó sinh ra đều sẽ có cùng order (trừ identity).

### Phần 2: RSA (DSA + forged plaintext)

Việc đầu tiên cần làm là tạo ra các smooth order $\mathbb{Z}_P$; ở đây mình giới hạn số nguyên tố chỉ 128 bit thôi cho dễ crack.
```python
def try_prime(cap=2**32):
    p = getPrime(128)
    factors = factorize_factordb(p-1)
    if factors is not None and max(factors.keys()) < cap:
        print(p)
        print(factors)
        
threads = []
for _ in trange(100000):
    t = Thread(target=try_prime)
    t.start()
    threads.append(t)
for t in tqdm(threads):
    t.join()
```

Trong đó, hàm `factorize_factordb` lấy các ước từ trang [factordb.com](factordb.com). Trong đó, các ước dài quá không hiện lên sẽ được skip, vì đằng nào nó cũng dài quá; nhưng sau này nếu cần bạn nên query link đó để lấy số cụ thể.
```python
def factorize_factordb(p: int) -> dict:
    result = requests.get(f'http://factordb.com/index.php?query={p}').text
    # only get fully factored
    status = re.search(r'\WFF\W', result)
    # if not found
    if status is None: return None
    ret = {}
    pattern = r'<a href="index.php\?id=\d+"><font color="#\d\d0000">(\d(?:[\d.]+)?)(?:\^(\d+))?<\/font><\/a>'
    for match in re.finditer(pattern, result):
        xp, mult = match.groups()
        if '.' in xp: return None
        ret[int(xp)] = int(mult or 1)
    return ret
```

Đây là vài giá trị mình có được:
```python
p1 = 238727251533741716722400942888398144591
f1 = {2: 1, 3: 5, 5: 1, 3659: 1, 5119: 1, 6709: 1, 1495633: 1, 252293677: 1, 2071853237: 1}
p2 = 333608929053242853170317622636449152139
f2 = {2: 1, 3: 1, 11: 1, 1373167: 1, 1640207: 1, 7028431: 1, 112211117: 1, 2845623511: 1}
p3 = 243252225961672840334482281305736742759
f3 = {2: 1, 3: 3, 23: 1, 29: 1, 97093697: 1, 103165889: 1, 569538457: 1, 1183823651: 1}

p = 268334761709516764273654696771078405403
p_ = {2: 1, 1109: 1, 102750629: 1, 342655031: 1, 1577600767: 1, 2178094333: 1}
```

Giờ chúng ta sinh ra tin nhắn và RSA MAC để crack:
```python
# reverse RSA-based DSA
message = b"ButBeingLeftIsHarderYesItsTru"
msg = int.from_bytes(pkcs15_pad(message, 256 // 8), 'big')
n, _, d = generate_key(prime_bitlength=128)
enc = RSA_encrypt(msg, n, d)
```

Như đề bài đã nói, plaintext (`msg`) và signature (`enc`) nên là primitive root của cả $p$ lẫn $q$. Ngoài ra, $pq>n$ để message/signature của chúng ta không bị wrap lại trong trường hợp xấu nhất. Chúng ta thử để chọn ra $q$, và nếu không tồn tại thì throw `RuntimeError` vì sẽ không giải được với các lựa chọn số nguyên tố này:
```python
if not is_primitive_root(enc, p, p_) or not is_primitive_root(msg, p, p_):
    # exit("Message/Signature is not a primitive root, please try again.")
    raise RuntimeError

if p * p1 > n and is_primitive_root(enc, p1, f1) and is_primitive_root(msg, p1, f1):
    q, q_ = p1, f1
elif p * p2 > n and is_primitive_root(enc, p2, f2) and is_primitive_root(msg, p2, f2):
    q, q_ = p2, f2
elif p * p3 > n and is_primitive_root(enc, p3, f3) and is_primitive_root(msg, p3, f3):
    q, q_ = p3, f3
else:
    # the primes are not good enough, try again
    # exit("Message/Signature is not a primitive root, please try again.")
    raise RuntimeError
```

Trong đó hàm `is_primitive_root` làm giống như trong hướng dẫn: check xem với tất cả các ước số có thể (ngoài 1 và chính nó) thì generator candidate đó có bị loop về 1 không:
```python
def get_all_factors(prime_factors: dict) -> list:
    factors = []
    primes = list(prime_factors.keys())
    iterators = [range(prime_factors[k] + 1) for k in primes]
    for exponents in product(*iterators):
        factor = 1
        for p, e in zip(primes, exponents):
            factor *= p ** e
        factors.append(factor)
    factors.sort()
    return factors

def is_primitive_root(g: int, p: int, order: dict) -> bool:
    # ignore 1 and itself
    for factor in get_all_factors(order)[1:-1]:
        if pow(g, factor, p) == 1:
            return False
    return True
```

Ngoài ra, chúng ta cần thuật toán Pohlig-Hellman để tính discrete log với smooth-order groups: code này có hỗ trợ tính song song để tăng tốc độ.
```python
def pohlig_hellman(y: int, g: int, p: int, order: dict, parallel=False):
    if len(order) == 1:
        x = 0
        for p_, e in order.items(): pass
        order = p_ ** e
        gamma = pow(g, p_ ** (e - 1), p)
        for k in range(e):
            h = pow(y * pow(g, order - x, p), pow(p_, e - 1 - k), p)
            d = bsgs(h, gamma, p_, p)
            x = (x + d * pow(p_, k)) % order
        return x
    else:
        params = []
        order_ = 1
        for p_, e in order.items():
            order_ *= p_ ** e
        factors = []
        for p_, e in order.items():
            factor = p_ ** e
            power = order_ // factor
            factors.append(factor)
            gi = pow(g, power, p)
            yi = pow(y, power, p)
            params.append([yi, gi, p, {p_: e}])
        if parallel:
            from multiprocessing import Pool, cpu_count
            remainders = Pool(cpu_count()).starmap(pohlig_hellman, params)
        else:
            from itertools import starmap
            remainders = starmap(pohlig_hellman, params)
        remainders = list(remainders)
        return chinese_remainder(factors, remainders)[0]
```

Và hàm đó cần sử dụng một hàm tính discrete log cơ bản chung chung. Ở đây mình sử dụng Shank's algo, hay còn gọi là [baby-step giant-step](https://en.wikipedia.org/wiki/Baby-step_giant-step):
```python
def bsgs(y, g, n, p):
    '''
    Baby step - Giant step aka Shank's algorithm to find discrete log
    Params:
        @y  point to find the discrete log
        @g  generator of the Abelian group
        @n  order of the group/generator
        @p  the GF(p) we're working with
    '''
    m = ceil_root(n, 2)
    hashtable = dict()
    for j in range(m):
        hashtable[pow(g, j, p)] = j
    
    invm = pow(g, (-m) % (p - 1), p)
    gamma = y
    for i in range(m):
        if gamma in hashtable:
            return i * m + hashtable[gamma]
        gamma = (gamma * invm) % p
```

Viết nốt code sinh ra bộ $(e', p, q)$:
```python
ep = pohlig_hellman(msg, enc, p, p_, True)
eq = pohlig_hellman(msg, enc, q, q_, True)

e = chinese_remainder([(p - 1) // 2, q - 1], [ep % ((p - 1) // 2), eq])[0]
new_msg = RSA_encrypt(enc, p * q, e)
assert msg == new_msg
```

Và phần còn lại là chạy: trong trường hợp $(p,q)$ không phù hợp, chúng ta chạy lại bài này để được secret private key khác :D

Câu cuối về việc decrypt RSA ra một plaintext bất kỳ chỉ đơn giản là chúng ta chọn $s$ là plaintext cần decrypt ra, thay public exponent $e$ bằng private key $d$, và giải $s^d=m \mod N$ tương tự.

# [Challenge 62: Key-Recovery Attacks on ECDSA with Biased Nonces](https://toadstyle.org/cryptopals/62.txt)

Do chúng ta sẽ phải làm việc với vector của các phân số, chúng ta sẽ code qua các hàm tính toán trên vector phân số:
```python
Vector = List[Fraction]

def add(v1: Vector, v2: Vector) -> Vector:
    assert len(v1) == len(v2), "Cannot add vectors of different dimensions!"
    return [x1 + x2 for (x1, x2) in zip(v1, v2)]

def sub(v1: Vector, v2: Vector) -> Vector:
    assert len(v1) == len(v2), "Cannot subtract vectors of different dimensions!"
    return [x1 - x2 for (x1, x2) in zip(v1, v2)]

def dot(v1: Vector, v2: Vector) -> Fraction:
    assert len(v1) == len(v2), "Cannot dot product vectors of different dimensions!"
    return sum([x1 * x2 for (x1, x2) in zip(v1, v2)])

def l2_sqr(v: Vector) -> Fraction:
    return dot(v, v)

def scale(v: Vector, s: Fraction) -> Vector:
    return [x * s for x in v]

def project(v1: Vector, v2: Vector) -> Vector:
    '''
    Project v1 upon v2.
    '''
    assert len(v1) == len(v2), "Cannot project vectors of different dimensions!"
    l22v2 = l2_sqr(v2)
    if l22v2 == 0: return [Fraction(0)] * len(v1)
    return scale(v2, dot(v1, v2) / l22v2)

def gram_schmidt(basis: List[Vector]) -> List[Vector]:
    new_basis = []
    for i, vec in enumerate(basis):
        for k in range(i):
            vec = sub(vec, project(vec, new_basis[k]))
        new_basis.append(vec)
    return new_basis
```

Đọc [pseudocode của LLL trên Wikipedia](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm#LLL_algorithm_pseudocode), chúng ta implement hàm LLL:
```python
def LLL(basis, delta=0.99):
    '''
    Lenstra-Lenstra-Lovasz to reduce a basis
    '''
    basis = basis[:]
    ortho = gram_schmidt(basis)

    def mu(i, j):
        v = basis[i]
        u = ortho[j]
        return dot(u, v) / dot(u, u)

    n = len(basis)
    k = 1

    while k < n:
        for j in reversed(range(k)):
            mu_ij = mu(k, j)
            if abs(mu_ij) > 1 / 2:
                basis[k] = sub(basis[k], scale(basis[j], round(mu_ij)))
                # ortho = gram_schmidt(basis)

        if l2_sqr(ortho[k]) >= (delta - mu(k, k - 1) ** 2) * l2_sqr(ortho[k-1]):
            k = k + 1
        else:
            basis[k], basis[k - 1] = basis[k - 1], basis[k]
            # since only two vectors swapped
            old_k1 = ortho[k - 1]
            ortho[k - 1] = add(ortho[k], project(basis[k - 1], old_k1))
            ortho[k] = sub(old_k1, project(old_k1, ortho[k - 1]))
            # ortho = gram_schmidt(basis) # <-- old code
            k = max(k - 1, 1)

    return basis
```

Trong đó, chúng ta phải optimize sao cho không phải chạy Gram-Schmidt mỗi iteration (vì thuật toán đó chạy rất lâu, $2n^3$ ops. Trong đó, có 2 chỗ đã sửa:
- Chỗ đầu tiên chúng ta xóa luôn code gọi Gram-Schmidt, vì đang trừ thành phần của $v_j$ khỏi $v_k$, với $v_j$ đã xuất hiện trước. Từ đó, basis thứ $k$ có thể chắc chắn đã không còn component nào của $v_j$, nên basis không đổi.
- Chỗ thứ chúng ta swap $v_{k-1}$ và $v_k$: vậy chúng ta chỉ cần sửa basis ở 2 vector đó thôi.
    - $v_k$ được chuyển lên trên, đồng nghĩa với việc chúng ta cần recover lại component của $v_{k-1}$ đã lọc từ lần Gram-Schmidt trước: project và cộng. Để ý là index của basis cần project phải là $k-1$ chứ không phải $k$, do chúng ta đã swap từ trước.
    - $v_{k-1}$ bị chuyển xuống dưới, nên chúng ta chỉ phải trừ đi component mới mà chúng ta vừa làm ở gạch đầu dòng trên: project rồi trừ.

Sửa mấy cái đó cần biết về đại số tuyến tính, nên đừng tưởng bài này dễ nhai không cần kiến thức như họ đã quảng cáo. Nhưng mà tin vui là xong hết mấy phần khó rồi, giờ là thủ tục thôi: đầu tiên là định nghĩa curve:
```python
curve = WeierstrassCurve(
        a = -95051,
        b = 11279326,
        p = 233970423115425145524320034830162017933,
        g = (182, 85518893674295321206118380980485522083),
        q = 29246302889428143187362802287225875743,
        order = (29246302889428143187362802287225875743 << 3)
    )
```

Và hàm ký sao cho 8 bit cuối của secret key bị zero out:
```python
def broken_sign(message, private_key, curve, hash_fn=sha256):
    q = curve.q

    # get the leftmost bits equal to the group order
    hashed = int.from_bytes(hash_fn(message).digest(), 'big')
    hashed >>= max(hashed.bit_length() - q.bit_length(), 0)

    # generate nonce key
    while True:
        private = randrange(1, curve.q)
        # zero out the last byte
        private ^= (private & 0xFF)
        public = curve.g * private
        k, r = private, public.x
        if r % q == 0: continue
        s = ((hashed + private_key * r) * invmod_prime(k, q)) % q
        if s != 0: break
        
    return hashed, r, s
```

Tạo key,
```python
# generate keys
secret, public = curve.generate_keypair()
```

Và ký vài (33) dòng lyrics:
```python
# sign like 33 messages for keepsake
text = "<chorus, bridge, và verse 2 của No Church In The Wild>"
text = text.replace('\n\n', '\n').split('\n')
print(len(text)) # 33
bases = []
for i in range(len(text)):
    bases.append([Fraction()] * i + [Fraction(curve.q)] + [Fraction()] * (len(text) - i + 1))
us = []
ts = []
for msg in text:
    msg = msg.encode()
    # H(m), r, s
    h, r, s = broken_sign(msg, secret, curve)
    # since we know q is prime
    s_inv = invmod_prime(s << 8, curve.q)
    t = (r * s_inv) % curve.q
    u = (-h * s_inv) % curve.q
    us.append(Fraction(u))
    ts.append(Fraction(t))
ts.append(Fraction(1, 256))
ts.append(Fraction())
us.append(Fraction())
us.append(Fraction(curve.q, 256))
bases.append(ts)
bases.append(us)
```

Chạy hàm LLL, mình mất 8 phút. Nếu không optimize thì mỗi iteration bị chậm đi phải tầm nghìn lần, nên đừng thử.
```python
bases = LLL(bases)
```

Và lấy lại secret key:
```python
recovered = []
for vector in bases:
    if vector[-1] == Fraction(curve.q, 256):
        recovered.append(int(vector[-2] * -256) % curve.q)
assert secret in recovered
```

# [Challenge 63: Key-Recovery Attacks on GCM with Repeated Nonces](https://toadstyle.org/cryptopals/63.txt)

Bài này sẽ rất khó. Để làm/hiểu được bài này cần rất nhiều kiến thức về number theory và abstract algebra.

Đầu tiên chúng ta viết code cho $\mathrm{GF}(2^{128})$. Vừa dễ sử dụng với polynomials, vừa có thể dùng các phép toán builtin. Trong đó, modulo được sử dụng `0x100000000000000000000000000000087` chính là $2^{128} + 2^7 + 2^2 + 2^1 + 2^0$, polynomial được sử dụng cho field extension.
```python
def _deg(x):
    assert x >= 0
    return x.bit_length() if x > 0 else -1

class GF2p128:
    def __init__(self, val=0, m=0x100000000000000000000000000000087):
        self.val = val
        self.m = m

    def __hash__(self):
        return hash((self.val, self.m))
    
    def __str__(self):
        return "GF2^128(" + str(self.val) + ')'
    
    def __repr__(self):
        return bin(self.val)[2:]

    def __add__(self, obj):
        assert self.m == obj.m, "Cannot add/sub numbers of different polynomial generators!"
        return GF2p128(self.val ^ obj.val, self.m)

    __sub__ = __add__

    def __mul__(self, obj):
        if type(obj) is int:
            return self if obj % 2 else GF2p128(0, self.m)
        assert self.m == obj.m, "Cannot multiply numbers of different polynomial generators!"
        a, b, m = self.val, obj.val, self.m
        p = 0

        while a:
            if a & 1:
                p ^= b
            
            a >>= 1
            b <<= 1

            if _deg(b) == _deg(m):
                b ^= m

        return GF2p128(p, m)

    def __pow__(self, power):
        if power < 0:
            return self.inv() ** -power

        a = self
        p = GF2p128(1, self.m)
        while power:
            if power & 1:
                p *= a
            a *= a
            power >>= 1
        return p

    def __truediv__(self, obj):
        return self * obj ** -1

    def __eq__(self, obj):
        if type(obj) is int:
            return self.val == obj
        if type(obj) is GF2p128:
            return self.m == obj.m and self.val == obj.val
        return False

    def __divmod__(self, obj):
        # in GF(2) only. GF(2^128) has no mod.
        assert self.m == obj.m, "Cannot divmod numbers of different polynomial generators!"
        q, r, b, m = 0, self.val, obj.val, self.m

        while _deg(r) >= _deg(b):
            d = _deg(r) - _deg(b)
            q = q ^ (1 << d)
            r = r ^ (b << d)

        return GF2p128(q, m), GF2p128(r, m)
    
    def inv(self):
        # Using EGCD
        m, n = self, GF2p128(self.m)
        m_coeff = (GF2p128(1), GF2p128(0))
        n_coeff = (GF2p128(0), GF2p128(1))

        while True:
            q, r = divmod(m, n)
            if r == 0:
                return n_coeff[0]
            m, n = n, r
            # q = m - n * r
            m_coeff, n_coeff = n_coeff, tuple(map(lambda x: x[0] - q * x[1], zip(m_coeff, n_coeff)))

    def inv_prime(self):
        '''
            Using Fermat's little theorem. Use the EGCD one because benchmarks.
                inv normal: 4.990437030792236
                inv prime : 95.93351244926453
        '''
        return pow(self, 2 ** 128 - 2)
```

Tiếp theo là hàm AEAD GCM. Hàm này sẽ nhận một tin nhắn và các data phụ, và trả về tin nhắn đã mã hoá + MAC cho mã hoá đó và data phụ.
```python
def gmac(key, msg, aad, nonce):
    '''
    Input:
        @key:   key to be encrypted/GMAC
        @msg:   message to be encrypted
        @aad:   additional associated data
        @nonce: 96-bit of nonce to XOR at the end
    '''
    authkey = AES_encrypt(key, b'\x00' * 16)
    authkey = GF2p128(int.from_bytes(authkey, 'big'))
    if msg is None:
        iv = encrypted = b''
    else:
        iv = generate_key(8)
        encrypted = iv + AES_encrypt(key, msg, 'ctr', iv)
    content = aad + b'\x00' * (-len(aad) % 16) + \
                encrypted + b'\x00' * (-len(encrypted) % 16) + \
                pack('>2Q', len(aad), len(encrypted))
    g = GF2p128(0)
    for i in range(0, len(content), 16):
        b = GF2p128(int.from_bytes(content[i : i + 16], 'big'))
        g += b
        g *= authkey
    s = AES_encrypt(key, nonce + b'\x00\x00\x00\x01')
    s = GF2p128(int.from_bytes(s, 'big'))
    g += s
    mac = int.to_bytes(g.val, 16, 'big')
    if msg is None:
        return mac
    else:
        return encrypted, mac
```

Để crack được authentication key, chúng ta cần một data structure để lưu polynomials. Sau là các hàm cơ bản, code không khó nhưng tốn thời gian debug. <sup>[1]</sup>
```python
class Polynomial:
    # coeffs are larger-order-first
    # order (p, e) is the p^e prime power order of the coeff field
    def __init__(self, coeff=None, num_class=None, order=None):
        if coeff is None:
            assert num_class is not None, "Cannot infer number type!"
            self.coeff = [num_class(0)]
        else:
            self.coeff = coeff[:]
        if num_class is None:
            self.num_class = type(coeff[0])
            assert len(self.coeff) > 0, "Cannot infer number type!"
        else:
            self.num_class = num_class
        
        if type(order) is int:
            self.order = (order, 1)
        elif order is None:
            if self.num_class is GF2p128:
                self.order = (2, 128)
            else:
                self.order = None
        else:
            self.order = order

        # inplace
        self._reduce()

    def __str__(self):
        return self.num_class.__name__ + ' polynomial: ' + (' + '.join(
            reversed([f'{v if (v.val != 1 or i == 0) else ""}{("x" + ("^" + str(i) if i > 1 else "")) if i > 0 else ""}' \
                for (i, v) in enumerate(reversed(self.coeff)) if v.val > 0])
        ) if self.deg() > 0 else str(self.coeff[0]))
    __repr__ = __str__

    def __eq__(self, obj):
        return len(self.coeff) == len(obj.coeff) and \
            all([x == y for (x, y) in zip(self.coeff, obj.coeff)])

    def copy(self, coeffs=None):
        return Polynomial(self.coeff if coeffs is None else coeffs,
                          self.num_class, self.order)

    def __hash__(self):
        return hash((tuple(self.coeff), self.num_class, self.order))

    def deg(self):
        return len(self.coeff) - 1
    
    def __call__(self, val):
        ret = self.num_class()
        for coeff in self.coeff:
            ret *= val
            ret += coeff
        return ret

    def _reduce(self):
        # remove leading zeros
        for i in range(len(self.coeff)):
            if self.coeff[i] != self.num_class(0):
                break
        del self.coeff[:i]
        return self

    def __add__(self, obj):
        assert type(self) == type(obj), "Can only add Polynomials with Polynomials!"
        longer, shorter = (self.copy(), obj) \
                          if self.deg() == max(self.deg(), obj.deg()) \
                          else (obj.copy(), self)
        diff = longer.deg() - shorter.deg()
        for i in range(shorter.deg() + 1):
            longer.coeff[diff + i] += shorter.coeff[i]
        return longer._reduce()

    def __sub__(self, obj):
        assert type(self) == type(obj), "Can only subtract Polynomials with Polynomials!"
        retval = self.copy()
        maxdeg = max(self.deg(), obj.deg())
        # pads result
        retval.coeff = [self.num_class(0)] * (maxdeg - self.deg()) + retval.coeff
        diff = maxdeg - obj.deg()
        for i in range(obj.deg() + 1):
            retval.coeff[diff + i] -= obj.coeff[i]
        return retval._reduce()

    def __mul__(self, obj):
        if type(obj) is self.num_class:
            return Polynomial([x * obj for x in self.coeff], order=self.order)
        assert type(self) is type(obj), "Can only multiply Polynomials with Polynomials!"
        total_deg = self.deg() + obj.deg()
        coeffs = [self.num_class()] * (total_deg + 1)
        for idx1, val1 in enumerate(self.coeff):
            for idx2, val2 in enumerate(obj.coeff):
                coeffs[idx1 + idx2] += val1 * val2
        return self.copy(coeffs)

    def __pow__(self, power, mod=None):
        ret = self.copy()
        ret.coeff = [ret.num_class(1)]
        acc = self.copy()
        while power > 0:
            if power & 1:
                ret *= acc
                if mod is not None:
                    ret %= mod
            power >>= 1
            acc *= acc
            if mod is not None:
                acc %= mod
        return ret

    def __truediv__(self, obj):
        if type(obj) is self.num_class:
            return self.copy([x / obj for x in self.coeff])
        quotient, remainder = divmod(self, obj)
        assert remainder == self.copy([self.num_class(0)]), 'Remainder not 0 in truediv!'
        return quotient

    def __floordiv__(self, obj):
        assert type(obj) is type(self)
        return divmod(self, obj)[0]

    def __mod__(self, obj):
        return divmod(self, obj)[1]

    def __divmod__(self, obj):
        assert type(self) is type(obj), "Can only divide Polynomials with Polynomials!"
        if self.deg() < obj.deg():
            return self.copy([self.num_class(0)]), self

        divider = self.copy()
        divided = obj << (divider.deg() - obj.deg())
        coeffs = []
        while divided.deg() >= obj.deg() and divided != self.copy([self.num_class(0)]):
            if divider.deg() < divided.deg():
                coeff = self.num_class(0)
            else:
                coeff = divider.coeff[0] / divided.coeff[0]
            divider -= divided * coeff
            divided >>= 1
            coeffs.append(coeff)
        return Polynomial(coeffs, self.num_class, self.order), divider

    def __lshift__(self, shift):
        retval = self.copy()
        retval.coeff += [self.num_class(0)] * shift
        return retval

    def __rshift__(self, shift):
        if shift > self.deg():
            return Polynomial(num_class=self.num_class, order=self.order)
        if shift == 0:
            return self
        return Polynomial(self.coeff[:-shift], self.num_class, self.order)
```

Chúng ta viết hàm chuyển polynomial về monic (khi coefficient ở leading term là 1):
```python
def monic(self):
    lead_coeff = self.coeff[0]
    return Polynomial([x / lead_coeff for x in self.coeff], self.num_class, self.order), lead_coeff
```

Hàm Extended Euclidean Algorithm để tìm GCD:
```python
def egcd(self, obj):
    # returns GCD, (coeff 1, coeff 2)
    m, n = self, obj
    zero = self.copy([self.num_class(0)])
    one = self.copy([self.num_class(1)])

    m_coeff = (one, zero)
    n_coeff = (zero, one)

    if m == zero:
        return n, n_coeff
    if n == zero:
        return m, m_coeff

    while True:
        q, r = divmod(m, n)
        assert r.deg() < n.deg() or r.deg() < 1
        assert q * n + r == m
        if r == Polynomial(num_class=self.num_class, order=self.order):
            n, coeff = n.monic()
            return n, (n_coeff[0] * coeff, n_coeff[1] * coeff)
        m, n = n, r
        # q = m - n * r
        m_coeff, n_coeff = n_coeff, tuple(map(lambda x: x[0] - q * x[1], zip(m_coeff, n_coeff)))
```

Hàm sinh ra đạo hàm, vì chúng ta sẽ cần lúc tính square-free factorization:
```python
def derivative(self):
    retval = self.copy()
    for i in range(self.deg()):
        retval.coeff[i] *= (self.deg() - i)
    return retval >> 1
```

Cả 3 hàm trong đề bài đều có thể tìm được ở [link Wikipedia này](https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields). Đây là hàm square-free factorization: đầu vào là một polynomial, và đầu ra là các factor kèm multiplicity, sao cho mỗi factor không còn ước bình phương nào nữa. Ý tưởng khá là hay: nếu chúng ta có factorization $f = \Pi_i f_i^{e_i}$ với $f_i$ là các ước polynomial tối giản (nguyên tố), thì đạo hàm sẽ là $f'=\sum_je_jf_j^{e_j-1}\Pi_{i\ne j}f_i^{e_i}$, và tất cả các số hạng trong tổng trên (và tổng trên, và cả $f$) sẽ đều có một ước chung là $\Pi_i f_i^{e_i-1}$. Từ đó, chúng ta sẽ có $f/\gcd(f, f')=\Pi_i f_i$.

```python
def sqr_free_factor(self):
    one = self.copy([self.num_class(1)])
    c = self.egcd(self.derivative())[0]
    w = self / c
    i = 1
    r = dict()
    # get all factors in w
    while w != one:
        y = w.egcd(c)[0]
        fac = w / y
        if fac != one:
            if fac in r:
                r[fac] += i
            else:
                r[fac] = i
        w = y
        c = c / y
        i += 1
    # get the rest from f
    if c != one:
        c = c.characteristic_root() #definition beloww
        for k, v in c.sqr_free_factor().items():
            if k in r:
                r[k] += v * self.order[0]
            else:
                r[k] = v * self.order[0]
    return r
```

Để tính được $p$-th root của một polynomial, hãy đọc [câu trả lời này trên Math.SE](https://math.stackexchange.com/a/1579112/402767). Thực sự khá là thú vị.
```python
def characteristic_root(self):
    # https://math.stackexchange.com/a/1579112/402767
    p, e = self.order
    retval = self.copy()
    retval.coeff = []
    for i in range(self.deg() + 1):
        if i % p: assert self.coeff[i] == self.num_class(0)
        else:
            retval.coeff.append(self.coeff[i] ** (p ** (e - 1)))
    return retval
```

Hàm different-degree factorization: đầu vào là một polynomial $f$, và đầu ra là các cặp đôi ước nhỏ $g$ của $f$, và degree $d$ của các ước nhỏ tối giản của $g$. Để hiểu được cụ thể thì khá khó, bạn có thể đọc [link Wikipedia](https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Distinct-degree_factorization) để tạm hiểu được ý tưởng.
```python
def diff_deg_factor(self):
    i = 1
    s = set()
    f = self
    one = self.copy([self.num_class(1)])
    p, e = self.order
    q = p ** e
    x = (one << 1)
    acc = pow(x, q, f)
    while f.deg() >= 2 * i:
        g = f.egcd(acc - x)[0]
        if g != one:
            s.add((g, i))
            f /= g
        i += 1

        # recalculate
        acc = pow(acc, q, f)

    if f != one:
        s.add((f, f.deg()))
    if len(s) == 0:
        return {(f, 1)}
    return s
```

Hàm Cantor-Zassenhaus, như đã được hướng dẫn. Để hiểu, bạn hãy đọc kỹ vài lần đoạn giải thích trong đề bài và [link Wikipedia trên](https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Cantor%E2%80%93Zassenhaus_algorithm). Đầu vào của hàm này là cặp polynomial $f$ và degree của ước của nó $d$, và đầu ra sẽ là các ước $g$ có degree $d$ của $f$.
```python
def random_polynomial(self):
    retval = self.copy()
    if retval.num_class is GF2p128:
        mod = retval.coeff[0].m
        for i in range(retval.deg() + 1):
            retval.coeff[i] = GF2p128(randrange(0, 2 ** 128), mod)
    else:
        raise NotImplementedError
    retval._reduce()
    return retval

def eq_deg_factor(self, degree):
    # Cantor-Zassenhaus algorithm for equal-degree factorization.
    f, d = self, degree
    p, e = self.order
    r = f.deg() // d
    factors = {f}
    one = self.copy([self.num_class(1)])

    while len(factors) < r:
        h = f.random_polynomial()
        g = h.egcd(f)[0]

        if g == one:
            g = (pow(h, (p ** (e * d) - 1) // 3, f) - one) % f

        for u in factors:
            if u.deg() > d:
                gcd_gu = g.egcd(u)[0]
                if gcd_gu != one and gcd_gu != u:
                    factors = (factors - {u}) | {gcd_gu, u / gcd_gu}

    return factors
```

Và một hàm tổng hợp để tìm tất cả các factor kèm multiplicity:
```python
def get_factors(self):
    retval = dict()
    for poly1, mult in self.sqr_free_factor().items():
        subfactor = poly1.diff_deg_factor()
        for poly2, degree in subfactor:
            for poly3 in poly2.eq_deg_factor(degree):
                if poly3 in retval:
                    retval[poly3] += mult
                else:
                    retval[poly3] = mult
    return retval
```

Chúng ta viết code sinh ra GMAC: nội dung cần MAC để trong AAD, và không encrypt gì cả:
```python
key = b'choppaAim@UrFace'
nonce = urandom(12)
def gcm_mac(data):
    return gmac(key, None, data, nonce)

msg1 = b'katarenai'
gmac1 = gcm_mac(msg1)
msg2 = b'nemurenai'
gmac2 = gcm_mac(msg2)
msg3 = b'toroimerai'
gmac3 = gcm_mac(msg3)

authkey = int.from_bytes(AES_encrypt(key, b'\x00' * 16), 'big')

def get_private_candidates(msg1, gmac1, msg2, gmac2):
    # build the blocks
    msg1 += b'\x00' * (-len(msg1) % 16) + pack('>2Q', len(msg1), 0)
    msg2 += b'\x00' * (-len(msg2) % 16) + pack('>2Q', len(msg2), 0)
    blocks1 = [GF2p128(int.from_bytes(msg1[i : i + 16], 'big')) for i in range(0, len(msg1), 16)]
    blocks2 = [GF2p128(int.from_bytes(msg2[i : i + 16], 'big')) for i in range(0, len(msg2), 16)]
    blocks1.append(GF2p128(int.from_bytes(gmac1, 'big')))
    blocks2.append(GF2p128(int.from_bytes(gmac2, 'big')))
    p = Polynomial(blocks1) + Polynomial(blocks2)
    return set([(x.coeff[1] / x.coeff[0]).val for x in p.get_factors() if x.deg() == 1])
```

Có tất cả mọi thứ rồi thì chúng ta chạy thôi:
```python
print('Getting candidate 1...')
candidates1 = get_private_candidates(msg1, gmac1, msg2, gmac2)
print('Getting candidate 2...')
candidates2 = get_private_candidates(msg2, gmac2, msg3, gmac3)
print('Getting candidate 3...')
candidates3 = get_private_candidates(msg1, gmac1, msg3, gmac3)
candidates = candidates1 & candidates2 & candidates3
assert len(candidates) == 1
for recovered in candidates: break
assert recovered == authkey
print('OK!')
```

Ở ví dụ trên mình sử dụng tin nhắn trong 1 block; bạn có thể test với các tin nhắn dài hơn nhiều để xem nó hoạt động nhé.

<sup>[1]</sup> Để debug, mình sẽ tặng bạn thêm một class $\mathrm{GF}(3)$ để có thể test xem các hàm đã đúng chưa. Hãy tạo các polynomial với các coefficients thuộc field này cho đơn giản dễ tính.

```python
class GF3:
    def __init__(self, val=0):
        self.val = val
    def __add__(self, obj):
        return GF3((self.val + obj.val) % 3)
    def __hash__(self):
        return hash(self.val)
    def __sub__(self, obj):
        return GF3((self.val - obj.val) % 3)
    def __mul__(self, obj):
        return GF3((self.val * (obj if type(obj) is int else obj.val)) % 3)
    def __truediv__(self, obj):
        return self * obj ** -1
    def __pow__(self, exp):
        if exp < 0:
            assert self.val > 0, "Cannot invert 0!"
        return GF3(pow(self.val, abs(exp), 3))
    def __str__(self):
        return str(self.val)
    __repr__ = __str__
    def __eq__(self, obj):
        return self.val == obj.val
```

# [Challenge 64: Key-Recovery Attacks on GCM with a Truncated MAC](https://toadstyle.org/cryptopals/64.txt)



# [Challenge 65: Truncated-MAC GCM Revisited: Improving the Key-Recovery Attack via Ciphertext Length Extension](https://toadstyle.org/cryptopals/65.txt)

# [Challenge 66: Exploiting Implementation Errors in Diffie-Hellman](https://toadstyle.org/cryptopals/66.txt)

***
**<div align="center">Hết thật rồi đó.</div>**
***