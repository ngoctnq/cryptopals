from utils import AES_encrypt, generate_key
from struct import pack
from random import randrange

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
            # elif self.num_class is GF3:
            #     self.order = (3, 1)
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

    def monic(self):
        lead_coeff = self.coeff[0]
        return Polynomial([x / lead_coeff for x in self.coeff], self.num_class, self.order), lead_coeff

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
            # print('m', m)
            # print('n', n)
            q, r = divmod(m, n)
            # print('q', q)
            # print('r', r)
            assert r.deg() < n.deg() or r.deg() < 1
            assert q * n + r == m
            if r == Polynomial(num_class=self.num_class, order=self.order):
                n, coeff = n.monic()
                return n, (n_coeff[0] * coeff, n_coeff[1] * coeff)
            m, n = n, r
            # q = m - n * r
            m_coeff, n_coeff = n_coeff, tuple(map(lambda x: x[0] - q * x[1], zip(m_coeff, n_coeff)))

    def derivative(self):
        retval = self.copy()
        for i in range(self.deg()):
            retval.coeff[i] *= (self.deg() - i)
        return retval >> 1

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
            c = c.characteristic_root()
            for k, v in c.sqr_free_factor().items():
                if k in r:
                    r[k] += v * self.order[0]
                else:
                    r[k] = v * self.order[0]
        return r

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


# test class
# class GF3:
#     def __init__(self, val=0):
#         self.val = val
#     def __add__(self, obj):
#         return GF3((self.val + obj.val) % 3)
#     def __hash__(self):
#         return hash(self.val)
#     def __sub__(self, obj):
#         return GF3((self.val - obj.val) % 3)
#     def __mul__(self, obj):
#         return GF3((self.val * (obj if type(obj) is int else obj.val)) % 3)
#     def __truediv__(self, obj):
#         return self * obj ** -1
#     def __pow__(self, exp):
#         if exp < 0:
#             assert self.val > 0, "Cannot invert 0!"
#         return GF3(pow(self.val, abs(exp), 3))
#     def __str__(self):
#         return str(self.val)
#     __repr__ = __str__
#     def __eq__(self, obj):
#         return self.val == obj.val

# p = Polynomial([GF3(x) for x in [1,0,2,2,0,1,1,0,2,2,0,1]], order=(3, 1))
# factors = p.sqr_free_factor()
# for factor in factors:
#     print(factor, factor.diff_deg_factor())