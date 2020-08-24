<sup>Đây là một bài trong series [Cùng giải Cryptopals!](https://viblo.asia/s/cung-giai-cryptopals-68Z00nw9ZkG).<br>Các bạn nên tự làm hoặc vừa đọc vừa làm thay vì đọc lời giải trực tiếp.</sup>
***
**<div align="center">Set này hiện tại không được publish trên trang chủ,<br>
và email thì cũng đến mùa quýt mới được trả lời,<br>
nên mình đã Google đề để làm  (｡・ ω<)ゞ</div>**
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

238727251533741716722400942888398144591
{2: 1, 3: 5, 5: 1, 3659: 1, 5119: 1, 6709: 1, 1495633: 1, 252293677: 1, 2071853237: 1}
333608929053242853170317622636449152139
{2: 1, 3: 1, 11: 1, 1373167: 1, 1640207: 1, 7028431: 1, 112211117: 1, 2845623511: 1}
268334761709516764273654696771078405403
{2: 1, 1109: 1, 102750629: 1, 342655031: 1, 1577600767: 1, 2178094333: 1}
243252225961672840334482281305736742759
{2: 1, 3: 3, 23: 1, 29: 1, 97093697: 1, 103165889: 1, 569538457: 1, 1183823651: 1}

# [Challenge 62: Key-Recovery Attacks on ECDSA with Biased Nonces](https://toadstyle.org/cryptopals/62.txt)

# [Challenge 63: Key-Recovery Attacks on GCM with Repeated Nonces](https://toadstyle.org/cryptopals/63.txt)

# [Challenge 64: Key-Recovery Attacks on GCM with a Truncated MAC](https://toadstyle.org/cryptopals/64.txt)

# [Challenge 65: Truncated-MAC GCM Revisited: Improving the Key-Recovery Attack via Ciphertext Length Extension](https://toadstyle.org/cryptopals/65.txt)

# [Challenge 66: Exploiting Implementation Errors in Diffie-Hellman](https://toadstyle.org/cryptopals/66.txt)

***
**<div align="center">Hết thật rồi đó.</div>**
***