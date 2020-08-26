from utils import AES_encrypt, generate_key
from struct import pack

class GF2p128:
    def __init__(self, val, m=0x100000000000000000000000000000087):
        self.val = val
        self.m = m
    
    def __str__(self):
        return str(self.val)
    
    def __repr__(self):
        return repr(self.val)

    def deg(self):
        x = self.val
        assert 0 <= x < 2 ** 128, "Number not in GF(2^128)!"
        if x == 0: return -1
        return x.bit_length()

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

            if b.bit_length() == m.bit_length():
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

        while r.bit_length() >= b.bit_length():
            d = r.bit_length() - b.bit_length()
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