from weierstrass import WeierstrassCurve, WeierstrassPoint
from multiprocessing import cpu_count, Pool, Value

class SomeCarryError(BaseException): pass

class BrokenCurve(WeierstrassCurve):
    def __init__(self, fail_freq=2**64):
        super().__init__(
            a = -95051,
            b = 11279326,
            p = 233970423115425145524320034830162017933,
            g = (182, 85518893674295321206118380980485522083),
            q = 29246302889428143187362802287225875743,
            order = (29246302889428143187362802287225875743 << 3)
        )
        self.fail_freq = fail_freq

    def point(self, x, y):
        return BrokenPoint(self, x, y)

class BrokenPoint(WeierstrassPoint):
    def __add__(self, obj):
        # if the star aligns, fail
        if (self.x * obj.x) % self.curve.fail_freq == 0:
            raise SomeCarryError
        ret = super().__add__(obj)
        ret.__class__ = self.__class__
        return ret
    
    def __mul__(self, scalar):
        assert isinstance(self, self.__class__) and isinstance(scalar, int), \
                'Can only multiply Point with a scalar.'
        scalar %= self.curve.q
        if scalar == 0: return self.curve.id
        # ignore first bit
        scalar = bin(scalar)[3:]
        acc = self
        for bit in scalar:
            acc += acc
            if bit == '1':
                acc += self
        return acc

curve = BrokenCurve(fail_freq=256)
recovered = Value('i')
recovered.value = 1

# ironic enough, this might fail due to the bug
print('Generating keypair...')
while True:
    try:
        private, public = curve.generate_keypair()
        assert private > 0
        break
    except (SomeCarryError, AssertionError):
        continue
print('Target :', bin(private)[2:])

def handshake(point):
    try:
        point * private
        return True
    except SomeCarryError:
        return False

def brute(_=None):
    while True:
        with recovered.get_lock():
            val = recovered.value
        # check if we got it
        if val == 0: return
        if curve.g * val == public:
            assert val == private
            print('\nOK')
            with recovered.get_lock():
                recovered.value = 0
            return val

        length = val.bit_length()
        add0 = val * 2
        add1 = add0 + 1

        while True:
            with recovered.get_lock():
                if recovered.value.bit_length() > length:
                    break
            found = False

            # try new points
            point = curve.generate_point()
            try: point * add0
            except SomeCarryError: succ0 = False
            else: succ0 = True
            try: point * add1
            except SomeCarryError: succ1 = False
            else: succ1 = True
            if succ0 ^ succ1:
                if not succ0:
                    if handshake(point):
                        trueval = add1
                        found = True
                if not succ1:
                    if handshake(point):
                        trueval = add0
                        found = True
            
            if found:
                with recovered.get_lock():
                    val = recovered.value
                    if val == 0: return
                    if val.bit_length() == length:
                        recovered.value = trueval
                        print(trueval & 1, end='', flush=True)

print('Solving: 1', end='', flush=True)
pool = Pool(cpu_count())
pool.map(brute, iterable=[None] * cpu_count())
# brute()