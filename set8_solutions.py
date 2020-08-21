from random import randrange
from hmac import digest
from rsa import invmod, int_to_bytes, chinese_remainder
from tqdm import trange, tqdm
from ecc import WeierstrassCurve, WeierstrassPoint, sqrtmod, ladder, jacobi_symbol

def chall57():
    p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
    g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143
    q = 236234353446506858198510045061214171961

    factors = [2, 5, 109, 7963, 8539, 20641, 38833, 39341, 46337, 51977, 54319, 57529]
    # keep only factors that sum up to be greater than q
    prod = 1
    for i, v in enumerate(factors):
        prod *= v
        if prod > q: break
    assert prod > q
    del factors[i + 1:]

    enclen = (p.bit_length() + 7) // 8
    msg = b"crazy flamboyant for the rap enjoyment"
    def get_mac(key: int, msg: bytes) -> bytes:
        return digest(key.to_bytes(enclen, 'big'), msg, 'md5')

    # bob's secret key
    secret = randrange(1, q)

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

    # do chinese remainder theorem
    recovered = 0
    for factor, remainder in zip(factors, remainders):
        factor_ = prod // factor
        inverse = invmod(factor_, factor)
        recovered = (recovered + remainder * inverse * factor_) % prod

    assert recovered == secret

def chall58():
    p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
    q = 335062023296420808191071248367701059461
    j = 34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702
    g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357

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
        for _ in trange(N):
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

    ##########
    # PART 1 #
    ##########

    # y = 7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119
    # res = pollard(y, 0, 2 ** 20)
    # assert pow(g, res, p) == y

    # y = 9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733
    # res = pollard(y, 0, 2 ** 40, k=25)
    # assert pow(g, res, p) == y

    ##########
    # PART 2 #
    ##########
    factors = [2, 12457, 14741, 18061, 31193, 33941, 63803]
    prod = 2 * 12457 * 14741 * 18061 * 31193 * 33941 * 63803

    enclen = (p.bit_length() + 7) // 8
    msg = b"crazy flamboyant for the rap enjoyment"
    def get_mac(key: int, msg: bytes) -> bytes:
        return digest(key.to_bytes(enclen, 'big'), msg, 'md5')

    # bob's key
    secret = randrange(1, q)
    public = pow(g, secret, p)

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

    # do chinese remainder theorem
    residue = 0
    for factor, remainder in zip(factors, remainders):
        factor_ = prod // factor
        inverse = invmod(factor_, factor)
        residue = (residue + remainder * inverse * factor_) % prod

    # y = g^x = g^(n + mr) = g^n + (g^r)^m
    m = pollard(
        (public * pow(g, q - residue, p)) % p,
        0,
        q // prod,
        k = 22,
        g = pow(g, prod, p)
    )
    recovered = prod * m + residue
    assert recovered == secret

def chall59():
    curve = WeierstrassCurve(
        a = -95051,
        b = 11279326,
        p = 233970423115425145524320034830162017933,
        g = (182, 85518893674295321206118380980485522083),
        q = 29246302889428143187362802287225875743,
        order = (29246302889428143187362802287225875743 << 3)
    )
    # test handshake
    priv_a, pub_a = curve.generate_keypair()
    priv_b, pub_b = curve.generate_keypair()
    assert pub_a * priv_b == pub_b * priv_a

    # according to ECIES, x coord is enough (uh, no?)
    # since y can be computed from x *without* the sign, we add that too
    msg = b"crazy flamboyant for the rap enjoyment"
    def get_mac(pubkey: WeierstrassPoint) -> bytes:
        return digest(int_to_bytes(pubkey.x, curve.p.bit_length()) + \
            (b'+' if pubkey.y * 2 < curve.p else b'-'), msg, 'md5')

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

    # try these 3 curves:
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

    recovered, modulus = chinese_remainder(
        factors1 + factors2 + factors3,
        remainders1 + remainders2 + remainders3
    )

    assert modulus >= curve.q
    assert recovered == priv_a

def chall60():
    p = 233970423115425145524320034830162017933
    q = 29246302889428143187362802287225875743
    a = 534 # b = 1
    assert ladder(4, q, a, p) == 0

    u = 76600469441198017145391791613091732004
    v = (u * u * u + a * u * u + u) % p
    print(ladder(u, 11, a, p))
    print(jacobi_symbol(v, p))

    # order of the twist
    q_ = 2 * p + 2 - q

chall60()