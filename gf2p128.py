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

    def inv(self):
        return pow(self, 2 ** 128 - 2)
