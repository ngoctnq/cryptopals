from utils import AES_encrypt, generate_key
from struct import pack


def _deg(x):
    assert x >= 0
    return x.bit_length() if x > 0 else -1

class GF2p128:
    def __init__(self, val, m=0x100000000000000000000000000000087):
        self.val = val
        self.m = m
    
    def __str__(self):
        return str(self.val)
    
    def __repr__(self):
        return repr(self.val)

    def __add__(self, obj):
        assert self.m == obj.m, "Cannot add/sub numbers of different polynomial generators!"
        return GF2p128(self.val ^ obj.val, self.m)

    __sub__ = __add__

    def __mul__(self, obj):
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

    def __div__(self, obj):
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
            Using Fermat's little theorem. Use the EGCD one because benchmarks:
                inv normal: 4.990437030792236
                inv prime : 95.93351244926453
        '''
        return pow(self, 2 ** 128 - 2)


def gmac(key, msg, nonce):
    authkey = AES_encrypt(key, b'\x00' * 16)
    authkey = GF2p128(int.from_bytes(authkey, 'big'))
    iv = generate_key(8)
    encrypted = iv + AES_encrypt(key, msg, 'ctr', iv)
    content = msg + b'\x00' * (-len(msg) % 16) + \
                encrypted + b'\x00' * (-len(encrypted) % 16) + \
                pack('>2Q', len(msg), len(encrypted))
    g = GF2p128(0)
    for i in range(0, len(content), 16):
        b = GF2p128(int.from_bytes(content[i : i + 16], 'big'))
        g += b
        g *= authkey
    s = AES_encrypt(key, nonce + b'\x00\x00\x00\x01')
    s = GF2p128(int.from_bytes(s, 'big'))
    g += s
    mac = int.to_bytes(g.val, 16, 'big')
    return encrypted, mac


class Polynomial:
    def __init__(self, coeff, num_class=GF2p128):
        self.coeff = coeff[:]
        self.num_class = GF2p128

    def __eq__(self, obj):
        return len(self.coeff) == len(obj.coeff) and all([x == y for (x, y) in zip(self.coeff, obj.coeff)])

    def copy(self):
        return Polynomial(self.coeff[:], self.num_class)

    def deg(self):
        return len(self.coeff) - 1
    
    def __call__(self, val):
        ret = 0
        for coeff in reversed(self.coeff):
            ret *= val
            ret += coeff
        return ret

    def __add__(self, obj):
        assert type(self) == type(obj), "Can only add Polynomials with Polynomials!"
        return Polynomial([x + y for (x, y) in zip(self.coeff, obj.coeff)], self.num_class)

    def __sub__(self, obj):
        assert type(self) == type(obj), "Can only subtract Polynomials with Polynomials!"
        return Polynomial([x - y for (x, y) in zip(self.coeff, obj.coeff)], self.num_class)

    def __mul__(self, obj):
        if type(obj) is self.num_class:
            return Polynomial([x * obj for x in self.coeff])
        assert type(self) is type(obj), "Can only multiply Polynomials with Polynomials!"
        total_deg = self.deg() + obj.deg()
        coeffs = [self.num_class()] * (total_deg + 1)
        for idx1, val1 in enumerate(self.coeff):
            for idx2, val2 in enumerate(obj.coeff):
                coeffs[total_deg - idx1 - idx2 + 1] += val1 * val2
        return Polynomial(coeffs, self.num_class)

    def __truediv__(self, obj):
        if type(obj) is self.num_class:
            return Polynomial([x / obj for x in self.coeff])
        return divmod(self, obj)[0]

    def __mod__(self, obj):
        return divmod(self, obj)[1]

    def __divmod__(self, obj):
        assert type(self) is type(obj), "Can only divide Polynomials with Polynomials!"
        
        divider = self.copy()
        coeffs = []
        while divider.deg() >= obj.deg():
            coeff = self[0] / obj[0]
            divided = obj.copy()
            divided.coeff += [GF2p128()] * (divider.deg() - obj.deg())
            divider -= divided * coeff
            coeffs.append(coeff)

        return Polynomial(coeffs, self.num_class), divider

    def monic(self):
        lead_coeff = self.coeff[0]
        return Polynomial([x / lead_coeff for x in self.coeff], self.num_class)

    def sqr_free_factor(self):
        ...

    def diff_deg_factor(self):
        ...

    def eq_deg_factor(self, degree):
        # Cantor-Zassenhaus algorithm for equal-degree factorization.
        f, d = self, degree
        n = f.deg()
        r = n // d
        S = {f}

        while len(S) < r:
            h = random_polynomial(1, f)
            g = gcd(h, f)

            if g == 1:
                g = (h ** ((q ** d - 1) / 3) - 1) % f

            for u in S:
                if u.deg() = d:
                    continue
                
                gcd_gu = gcd(g, u)
                if gcd_gu != 1 and gcd_gu != u:
                    S = (S - {u}) | ({gcd_gu, u / gcd_gu})

        return S