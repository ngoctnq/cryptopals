from random import randrange, seed
from hmac import digest
from rsa import int_to_bytes, chinese_remainder, generate_key, pkcs15_pad, getPrime, RSA_encrypt
from tqdm import trange, tqdm
from utils import sqrtmod, jacobi_symbol, invmod, invmod_prime, factorize_factordb, is_primitive_root, pohlig_hellman
from weierstrass import WeierstrassCurve, WeierstrassPoint
from montgomery import _ladder as ladder
from pprint import pprint
from threading import Thread
from hashlib import sha256
from fractions import Fraction
from linalg import LLL

def chall57():
    p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
    # g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143
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
    # j = 34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702
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

# chall60 is in a separate file.

def chall61():
    # from ecc import sign, verify
    # from hashlib import sha256
    # curve = WeierstrassCurve(
    #     a = -95051,
    #     b = 11279326,
    #     p = 233970423115425145524320034830162017933,
    #     g = (182, 85518893674295321206118380980485522083),
    #     q = 29246302889428143187362802287225875743,
    #     order = (29246302889428143187362802287225875743 << 3)
    # )
    # private, public = curve.generate_keypair()

    # message = b"leavin' is the hardest thing to do"
    # signature = sign(message, private, curve)
    # assert verify(message, signature, public)

    # # copy straight from verify code
    # r, s = signature
    # q = curve.q
    # hashed = int.from_bytes(sha256(message).digest(), 'big')
    # hashed >>= max(hashed.bit_length() - q.bit_length(), 0)
    # s_inv = invmod_prime(s, q)
    # u1 = (hashed * s_inv) % q
    # u2 = (r * s_inv) % q
    # # craft public key
    # d_ = randrange(1, q)
    # t = (u1 + u2 * d_) % q
    # R = u1 * curve.g + u2 * public
    # g_ = invmod(t, q) * R
    # Q_ = d_ * g_
    # Q_.curve = WeierstrassCurve(
    #     a = -95051,
    #     b = 11279326,
    #     p = 233970423115425145524320034830162017933,
    #     g = (g_.x, g_.y),
    #     q = 29246302889428143187362802287225875743,
    #     order = (29246302889428143187362802287225875743 << 3)
    # )
    # assert verify(message, signature, Q_)

    # reverse RSA-based DSA
    message = b"ButBeingLeftIsHarderYesItsTru"
    msg = int.from_bytes(pkcs15_pad(message, 256 // 8), 'big')
    n, _, d = generate_key(prime_bitlength=128)
    enc = RSA_encrypt(msg, n, d)

    # def try_prime(cap=2**32):
    #     p = getPrime(128)
    #     factors = factorize_factordb(p-1)
    #     if factors is not None and max(factors.keys()) < cap:
    #         print(p)
    #         print(factors)
            
    # threads = []
    # for _ in trange(100000):
    #     t = Thread(target=try_prime)
    #     t.start()
    #     threads.append(t)
    # for t in tqdm(threads):
    #     t.join()

    p1 = 238727251533741716722400942888398144591
    f1 = {2: 1, 3: 5, 5: 1, 3659: 1, 5119: 1, 6709: 1, 1495633: 1, 252293677: 1, 2071853237: 1}
    p2 = 333608929053242853170317622636449152139
    f2 = {2: 1, 3: 1, 11: 1, 1373167: 1, 1640207: 1, 7028431: 1, 112211117: 1, 2845623511: 1}
    p3 = 243252225961672840334482281305736742759
    f3 = {2: 1, 3: 3, 23: 1, 29: 1, 97093697: 1, 103165889: 1, 569538457: 1, 1183823651: 1}
    
    p = 268334761709516764273654696771078405403
    p_ = {2: 1, 1109: 1, 102750629: 1, 342655031: 1, 1577600767: 1, 2178094333: 1}
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

    ep = pohlig_hellman(msg, enc, p, p_, True)
    eq = pohlig_hellman(msg, enc, q, q_, True)

    e = chinese_remainder([(p - 1) // 2, q - 1], [ep % ((p - 1) // 2), eq])[0]
    new_msg = RSA_encrypt(enc, p * q, e)
    assert msg == new_msg

def chall62():
    curve = WeierstrassCurve(
        a = -95051,
        b = 11279326,
        p = 233970423115425145524320034830162017933,
        g = (182, 85518893674295321206118380980485522083),
        q = 29246302889428143187362802287225875743,
        order = (29246302889428143187362802287225875743 << 3)
    )

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
    
    # generate keys
    secret, public = curve.generate_keypair()
    # sign like 33 messages for keepsake
    text = """[Chorus: Frank Ocean]\nHuman beings in a mob\nWhat's a mob to a king? What's a king to a god?\nWhat's a god to a non-believer who don't believe in anything?\nWill he make it out alive? Alright, alright, no church in the wild\n\n[Bridge: The-Dream]\nI live by you, desire\nI stand by you, walk through the fire\nYour love is my scripture\nLet me in through your encryption\nYeah, yeah\n\n[Verse 2: Kanye West]\nCoke on her black skin made it stripe like a zebra\nI call that jungle fever\nYou will not control the threesome\nJust roll the weed up until I get me some\nWe formed a new religion\nNo sins as long as there’s permission\nAnd deception is the only felony\nSo never fuck nobody without telling me\nSunglasses and Advil\nLast night was mad real\nSun coming up, 5 a.m\nI wonder if they got cabs still\nThinking 'bout the girl in all leopard\nWho was rubbing the wood like Kiki Shepard\nTwo tattoos: one read "No Apologies"\nThe other said "Love is Cursed by Monogamy"\nIt’s something that the pastor don’t preach\nIt’s something that a teacher can’t teach\nWhen we die, the money we can’t keep\nBut we probably spend it all 'cause the pain ain’t cheap\nPreach"""
    text = text.replace('\n\n', '\n').split('\n')
    # print(len(text)) # 34
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

    bases = LLL(bases)
    recovered = []
    for vector in bases:
        if vector[-1] == Fraction(curve.q, 256):
            recovered.append(int(vector[-2] * -256) % curve.q)
    assert secret in recovered

def chall63():
    ...

chall63()