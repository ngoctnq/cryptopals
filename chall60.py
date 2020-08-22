from montgomery import MontgomeryCurve, _ladder
from utils import jacobi_symbol, chinese_remainder, sqrtmod
from random import randrange
from tqdm.auto import tqdm, trange

curve = MontgomeryCurve(
    a = 534,
    b = 1,
    p = 233970423115425145524320034830162017933,
    g = (4, 85518893674295321206118380980485522083),
    q = 29246302889428143187362802287225875743,
    order = (29246302889428143187362802287225875743 << 3)
)

# assert _ladder(4, self.q, self.a, self.p) == 0

# u = 76600469441198017145391791613091732004
# v = (u * u * u + a * u * u + u) % p
# print(_ladder(u, 11, curve.a, curve.p))
# print(jacobi_symbol(v, p))

# order of the twist
q_ = 2 * curve.p + 2 - curve.order # = 2^2 x 11 x 107 x 197 x 1621 x 105143 x 405373 x 2323367 x ...

from hmac import digest
def get_mac(pubkey: int) -> bytes:
    return digest(
        int.to_bytes(pubkey, curve.p.bit_length() // 8 + 1, 'big'),
        b"crazy flamboyant for the rap enjoyment",
        'md5'
    )

# multiprocessing code
from multiprocessing import Pool, cpu_count, Value, Process
from itertools import repeat

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

# process
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

secret = randrange(1, curve.q)
public = _ladder(4, secret, curve.a, curve.p)
factors = [11, 107, 197, 1621, 105143, 405373, 2323367]
remainders = []

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

y = sqrtmod((public ** 3 + curve.a * public ** 2 + public) % curve.p, curve.p)
public = curve.point(public, y)

def pollard(y, min_exp, max_exp, g, k=16, progress=True):
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
            print(max_exp + xT - xW)
            return max_exp + xT - xW

# y = g^x = g^(n + mr) = g^n + (g^r)^m
# parallel compute all 4 instances
procs = []
pollard_mod = 23
print(secret)
param = True
for remainder in remainders:
    procs.append(Process(target=pollard,
        args=(
            public - curve.g * remainder,
            0,
            curve.q // factor,
            curve.g * factor,
            pollard_mod,
            param
        )
    ))
    if param: param = False
    procs.append(Process(target=pollard,
        args=(
            -public - curve.g * remainder,
            0,
            curve.q // factor,
            curve.g * factor,
            pollard_mod,
            param
        )
    ))
for proc in procs:
    proc.start()
for proc in procs:
    proc.join()