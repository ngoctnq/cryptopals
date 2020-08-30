from abc import abstractmethod, ABC
from random import randrange
from hashlib import sha256
from utils import invmod_prime

class EllipticCurve(ABC):

    @abstractmethod
    def point(self, x, y): pass

    def __eq__(self, obj):
        # same config different object is different curve
        # this is to prevent recursive comparison
        return id(self) == id(obj)

    # pylint: disable=no-member
    def generate_keypair(self):
        private = randrange(1, self.q)
        public = self.g * private
        return private, public
    
    def generate_point(self):
        return self.generate_keypair[1]


class EllipticPoint(ABC):

    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y

    def __str__(self):
        return f'{(self.x, self.y) if self != self.curve.id else "Identity"}'
    
    __repr__ = __str__

    def copy(self):
        # shallow copy
        return self.__class__(self.curve, self.x, self.y)

    def __neg__(self):
        return self.__class__(self.curve, self.x, self.curve.p - self.y)

    def __eq__(self, obj):
        return self.curve == obj.curve and self.x == obj.x and self.y == obj.y

    def __sub__(self, obj):
        assert isinstance(self, self.__class__) and isinstance(obj, self.__class__), \
                'Can only subtract Point with another Point.'
        return self + (-obj)
    
    @abstractmethod
    def _add(self, obj): pass

    @abstractmethod
    def _double(self): pass

    def __add__(self, obj):
        assert isinstance(self, self.__class__) and isinstance(obj, self.__class__), \
                'Can only add Point with another Point.'
        # assert self.curve == obj.curve, 'Points must be of the same curve.'
        
        curve = self.curve
        if self == curve.id:
            return obj
        if obj == curve.id:
            return self
        if self == -obj:
            return curve.id

        if self == obj:
            return self._double()
        else:
            return self._add(obj)

    def __mul__(self, scalar):
        assert isinstance(self, self.__class__) and isinstance(scalar, int), \
                'Can only multiply Point with a scalar.'
        scalar %= self.curve.q
        pow2 = self
        acc = self.curve.id
        while True:
            if scalar & 1:
                acc += pow2
            scalar >>= 1
            if scalar == 0: return acc
            pow2 += pow2
    
    def __rmul__(self, scalar):
       return self * scalar


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