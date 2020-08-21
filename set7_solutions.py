import requests
from utils import (
    stream_xor,
    pkcs7_pad,
    AES_encrypt,
    hexlify,
    generate_key,
    b64encode,
    b64decode,
    pkcs7,
    randint,
    trange
)
from zlib import compress
from string import ascii_letters, digits
from itertools import product
from md4 import F, G, MD4, leftrotate, struct
from threading import Lock

def chall49():
    # part 1
    valid = requests.post('http://localhost:9000/sign', json={
        'acc_from': 6, 'acc_to': 9, 'amount': 1000000
    }).content
    assert requests.post('http://localhost:9000/send', data=valid).status_code == 200

    payload = list(valid)
    payload[5] = ord('8')
    payload[5 + 16 * 2] ^= ord('6') ^ ord('8')
    payload = bytes(payload)
    assert payload[:-32] == b'from=8&to=9&amount=1000000'
    assert requests.post('http://localhost:9000/send', data=valid).status_code == 200

    #======================#

    # part 2
    victim_mac = requests.post('http://localhost:9000/sign2', json={
        'acc_from': 8,
        'txlist': {
            7: 123
        }
    }).content
    assert requests.post('http://localhost:9000/send2', data=victim_mac).status_code == 200
    
    # get victim's MAC
    victim_content = victim_mac[:-16]
    victim_mac = victim_mac[-16:]

    # get attacker's MAC
    attacker_mac = requests.post('http://localhost:9000/sign2', json={
        'acc_from': 6,
        'txlist': {
            0: 1,
            9: 1000000
        }
    }).content
    assert requests.post('http://localhost:9000/send2', data=attacker_mac).status_code == 200

    attacker_content = attacker_mac[:-16]
    attacker_mac = attacker_mac[-16:]

    # craft payload
    payload = pkcs7_pad(victim_content) + stream_xor(attacker_content[:16], victim_mac) + attacker_content[16:] + attacker_mac
    assert requests.post('http://localhost:9000/send2', data=payload).status_code == 200

    # make sure payload sends me 1M bucks
    params = dict(map(lambda x: x.split(b'='), payload.split(b'&')))
    assert params[b'from'] == b'8' and b'9:1000000' in params[b'txlist']

def chall50():
    def hash_cbc(msg: bytes) -> bytes:
        return AES_encrypt(b"YELLOW SUBMARINE", pkcs7_pad(msg), 'cbc')[-16:]
    
    original = b"alert('MZA who was that?');\n"
    assert hexlify(hash_cbc(original)) == b'296b8d7cb78a243dda4d0a61d33bbdd1'

    modified = b"alert('Ayo, the Wu is back!');//"
    modified += \
        stream_xor(
            original[:16],
            AES_encrypt(b"YELLOW SUBMARINE", modified, 'cbc')[-16:]
        ) + original[16:]
    print(hexlify(hash_cbc(modified)), b'296b8d7cb78a243dda4d0a61d33bbdd1')

def chall51():
    sessionid = 'TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='
    def compression_oracle(P: bytes):
        req = f'POST / HTTP/1.1\nHost: hapless.com\nCookie: sessionid={sessionid}\nContent-Length: {len(P)}\n'.encode() + P
        # for CTR, i.e. length is as-is
        # return len(AES_encrypt(generate_key(), compress(req), 'ctr', generate_key(8)))
        # for CBC, i.e length is paddad
        # return len(AES_encrypt(generate_key(), pkcs7_pad(compress(req)), 'cbc', generate_key(16)))
        # for the lazy, i.e. me
        return len(pkcs7_pad(compress(req)))
    
    payload_prefix = 'sessionid='
    charset = ascii_letters + digits + '+='
    candidates = ['']
    final_candidate = None
    
    while not final_candidate:
        min_compressed = None
        min_candidates = []
        for prefix, char in product(candidates, charset):
            if '=' in prefix and char != '=': continue
            sessid = prefix + char
            payload = (payload_prefix + sessid).encode()
            compressed_size = [compression_oracle(b'\n'.join([payload] * 2 ** i)) for i in range(4)]
            if min_compressed is None:
                min_compressed = compressed_size
                min_candidates = [sessid]
            elif min_compressed >= compressed_size:
                if min_compressed == compressed_size:
                    min_candidates.append(sessid)
                else:
                    min_compressed = compressed_size
                    min_candidates = [sessid]
        # filter the candidates
        candidates = []
        for candidate in min_candidates:
            if '=' in candidate:
                if len(min_candidates) < 50:
                    final_candidate = b64encode(b64decode(candidate + '==')).decode()
                    break
            else:
                candidates.append(candidate)
        print(len(candidates))

    print(final_candidate)
    assert sessionid == final_candidate

def chall52():
    def f(msg: bytes, h: bytes = b'\x06\x09'):
        # output is 16 bit/2 bytes
        assert len(h) == 2
        assert len(msg) % 16 == 0
        for i in range(0, len(msg), 16):
            # pads on the right, truncate the left
            h = AES_encrypt(msg[i:i+16], pkcs7(h, 14))[-2:]
        return h

    def g(msg: bytes, h: bytes = b'\x04\x02\x00'):
        # output is 24 bit/3 bytes
        assert len(h) == 3
        assert len(msg) % 16 == 0
        for i in range(0, len(msg), 16):
            # pads on the right, truncate the left
            h = AES_encrypt(msg[i:i+16], pkcs7(h, 13))[-3:]
        return h

    f_count = 0
    g_count = 0

    # generate 2^12 hash collisions (i.e. 12 blocks)
    fragments = []
    hashes = [b'\x06\x09']
    for i in range(12):
        found = {}
        for block in product(range(256), repeat=16):
            f_count += 1
            block = bytes(block)
            hash_ = f(block, hashes[i])
            if hash_ in found:
                found[hash_].append(block)
                fragments.append(found[hash_])
                hashes.append(hash_)
                break
            else:
                found[hash_] = [block]

    print('Generating 2^12 f-collisions took', f_count, 'tries.')
    # check for g collisions
    found = False
    trials = [b'']
    for i in range(12):
        for j in range(len(trials)):
            trials.append(trials[j] + fragments[i][0])
            trials[j] += fragments[i][1]
        g_hashes = {}
        for msg in trials:
            g_count += 1
            g_hash = g(msg)
            if g_hash in g_hashes:
                msg_ = g_hashes[g_hash]
                found = True
                break
            else:
                g_hashes[g_hash] = msg
        if found: break
    if found:
        print('Found collision!')
        assert f(msg) == f(msg_) and g(msg) == g(msg_)
        print('Total calls to check for g-collisions:', g_count)
    else:
        print('Collision for g not found. Generating more...', g_count)
        i = 12
        while not found:
            # generate new f
            found = {}
            for block in product(range(256), repeat=16):
                f_count += 1
                block = bytes(block)
                hash_ = f(block, hashes[i])
                if hash_ in found:
                    found[hash_].append(block)
                    fragments.append(found[hash_])
                    hashes.append(hash_)
                    break
                else:
                    found[hash_] = [block]
            # recheck g collisions
            for j in range(len(trials)):
                trials.append(trials[j] + fragments[i][0])
                trials[j] += fragments[i][1]
            g_hashes = {}
            for msg in trials:
                g_count += 1
                g_hash = g(msg)
                if g_hash in g_hashes:
                    msg_ = g_hashes[g_hash]
                    found = True
                    break
                else:
                    g_hashes[g_hash] = msg
            if found:
                print('Found collision!')
                assert f(msg) == f(msg_) and g(msg) == g(msg_)
                print('Total calls to generate f-collisions:', f_count, 'tries.')
                print('Total calls to check for g-collisions:', g_count)
            else:
                # life goes on
                i += 1

def chall53(block_size=8, hash_size=4, original_state=None, msg_log_len=20):
    if original_state is None:
        original_state = generate_key(hash_size)
    assert 16 % block_size == 0
    def toy_hash(msg: bytes, h: bytes = original_state, partial=True, keep_states=False):
        assert len(h) == hash_size
        if partial:
            assert len(msg) % block_size == 0
        else:
            msg = pkcs7(msg, block_size - (len(msg) % block_size))
        if keep_states:
            states = []
            ranger = trange
        else:
            ranger = range
        for i in ranger(0, len(msg), block_size):
            # pads on the right, truncate the left
            h = AES_encrypt(msg[i : i + block_size] * (16 // block_size),
                            pkcs7(h, 16 - hash_size))[-hash_size:]
            if keep_states:
                states.append(h)
        if not keep_states:
            return h
        else:
            return states
    
    def get_collision(state1, state2):
        hashes1 = {}
        hashes2 = {}
        for block in product(range(256), repeat=block_size):
            block = bytes(block)
            hash1 = toy_hash(block, state1)
            hash2 = toy_hash(block, state2)
            if hash1 in hashes1: continue
            else: hashes1[hash1] = block
            if hash2 in hashes2: continue
            else: hashes2[hash2] = block
            union = hashes1.keys() & hashes2.keys()
            if len(union) >= 1:
                state = union.pop()
                return hashes1[state], hashes2[state], state

    # 2^msg_log_len blocks + less than a block
    print('Getting orignal string hashes...')
    original = generate_key(2 ** msg_log_len * block_size + randint(1, block_size - 1))
    states = dict((v, k) for k, v in enumerate(toy_hash(original, partial=False, keep_states=True)) \
                         if msg_log_len <= k < 2 ** msg_log_len)

    # build the expandable message
    print('Building expandable message...')
    state = original_state
    messages = []
    for i in trange(msg_log_len):
        prefix = generate_key(2 ** (msg_log_len - i - 1) * block_size)
        state2 = toy_hash(prefix, state)
        msg1, msg2, state = get_collision(state, state2)
        messages.append([msg1, prefix + msg2])

    # find the connector block
    print('Finding connector block', end='', flush=True)
    i = 0
    for block in product(range(256), repeat=block_size):
        i += 1
        if i % 10000 == 0: print('.', end='', flush=True)
        block = bytes(block)
        hash_ = toy_hash(block, state)
        if hash_ in states:
            block_count = states[hash_]
            # get the expandable message of desired length
            crafted = b''
            crafted_block_count = block_count - msg_log_len
            for i, (c1, c2) in enumerate(messages):
                if crafted_block_count < 2 ** (msg_log_len - i - 1):
                    crafted += c1
                else:
                    crafted += c2
                    crafted_block_count -= 2 ** (msg_log_len - i -1)
            crafted += block + original[block_size * (block_count + 1):]
            break
    
    assert original != crafted and len(original) == len(crafted) and \
        toy_hash(original, partial=False) == toy_hash(crafted, partial=False)
    print('\nOK!')

# this won't run. just pseudocode.
# def chall54():
#     # for some fixed k
#     k = 10
#     # and some initial messages of the same length filling a whole block
#     msgs = [...]
#     lens = map(len, msgs)
#     assert len(msg) == 2 ** k and max(lens) == min(lens) and min(lens) % block_size == 0
#     msgs = [msgs]
#     hashes = [list(map(hash_fn, msgs))]
#     tails = []
#     for i in range(k):
#         tail = []
#         states = []
#         for j in range(0, 2 ** i, 2):
#             msg1, msg2, state = get_collision(hashes[i][j], hashes[i][j+1])
#             tail.append(msg1)
#             tail.append(msg2)
#             states.append(state)
#         tails.append(tail)
#         hashes.append(states)
#     # then do things with hashes[-1][-1]


from multiprocessing import Process, cpu_count, Value
count = Value('i', 0)
def chall55():
    def bit_at(num, i):
        # 0 is least significant
        return (num >> i) & 1
    def correct(num, rules):
        # rules is dict({idx, bit_value})
        for idx, val in rules.items():
            assert val in (0, 1)
            if val == 0:
                num ^= (bit_at(num, idx) << idx)
            else:
                num |= (1 << idx)
        return num
    def round1(a, b, c, d, lrot, m):
        return leftrotate((a + F(b, c, d) + m) & 0xFFFFFFFF, lrot)
    def fix1(a, b, c, d, lrot, old_a):
        return (leftrotate(a, 32 - lrot) - old_a - F(b, c, d)) % 0x100000000

    print('Running attack...')
    def search_thread():
        global count
        while True:
            with count.get_lock():
                if count.value == -1 or count.value > 2 ** 30: break
                count.value += 1
                if count.value % (1 << 16) == 0: print('.', end='', flush=True)
                if count.value % (9 << 19) == 0: print()
            original = generate_key(64)
            a, b, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
            m = list(struct.unpack("<16I", original))
            # condition the collided msg
            # rule 1
            old_val = a
            a = round1(a, b, c, d, 3, m[0])
            a = correct(a, {
                6: bit_at(b, 6)
            })
            m[0] = fix1(a, b, c, d, 3, old_val)
            # rule 2
            old_val = d
            d = round1(d, a, b, c, 7, m[1])
            d = correct(d, {
                6: 0,
                7: bit_at(a, 7),
                10: bit_at(a, 10)
            })
            m[1] = fix1(d, a, b, c, 7, old_val)
            # rule 3
            old_val = c
            c = round1(c, d, a, b, 11, m[2])
            c = correct(c, {
                6: 1,
                7: 1,
                10: 0,
                25: bit_at(d, 25)
            })
            m[2] = fix1(c, d, a, b, 11, old_val)
            # rule 4
            old_val = b
            b = round1(b, c, d, a, 19, m[3])
            b = correct(b, {
                6: 1,
                7: 0,
                10: 0,
                25: 0
            })
            m[3] = fix1(b, c, d, a, 19, old_val)
            # rule 5
            old_val = a
            a = round1(a, b, c, d, 3, m[4])
            a = correct(a, {
                7: 1,
                10: 1,
                25: 0,
                13: bit_at(b, 13)
            })
            m[4] = fix1(a, b, c, d, 3, old_val)
            # rule 6
            old_val = d
            d = round1(d, a, b, c, 7, m[5])
            d = correct(d, {
                13: 0,
                18: bit_at(a, 18),
                19: bit_at(a, 19),
                20: bit_at(a, 20),
                21: bit_at(a, 21),
                25: 1
            })
            m[5] = fix1(d, a, b, c, 7, old_val)
            # rule 7
            old_val = c
            c = round1(c, d, a, b, 11, m[6])
            c = correct(c, {
                12: bit_at(d, 12),
                13: 0,
                14: bit_at(d, 14),
                18: 0,
                19: 0,
                20: 1,
                21: 0
            })
            m[6] = fix1(c, d, a, b, 11, old_val)
            # rule 8
            old_val = b
            b = round1(b, c, d, a, 19, m[7])
            b = correct(b, {
                12: 1,
                13: 1,
                14: 0,
                16: bit_at(c, 16),
                18: 0,
                19: 0,
                20: 0,
                21: 0
            })
            m[7] = fix1(b, c, d, a, 19, old_val)
            # rule 9
            old_val = a
            a = round1(a, b, c, d, 3, m[8])
            a = correct(a, {
                12: 1,
                13: 1,
                14: 1,
                16: 0,
                18: 0,
                19: 0,
                20: 0,
                22: bit_at(b, 22),
                21: 1,
                25: bit_at(b, 25)
            })
            m[8] = fix1(a, b, c, d, 3, old_val)
            # rule 10
            old_val = d
            d = round1(d, a, b, c, 7, m[9])
            d = correct(d, {
                12: 1,
                13: 1,
                14: 1,
                16: 0,
                19: 0,
                20: 1,
                21: 1,
                22: 0,
                25: 1,
                29: bit_at(a, 29)
            })
            m[9] = fix1(d, a, b, c, 7, old_val)
            # rule 11
            old_val = c
            c = round1(c, d, a, b, 11, m[10])
            c = correct(c, {
                16: 1,
                19: 0,
                20: 0,
                21: 0,
                22: 0,
                25: 0,
                29: 1,
                31: bit_at(d, 31)
            })
            m[10] = fix1(c, d, a, b, 11, old_val)
            # rule 12
            old_val = b
            b = round1(b, c, d, a, 19, m[11])
            b = correct(b, {
                19: 0,
                20: 1,
                21: 1,
                22: bit_at(c, 22),
                25: 1,
                29: 0,
                31: 0
            })
            m[11] = fix1(b, c, d, a, 19, old_val)
            # rule 13
            old_val = a
            a = round1(a, b, c, d, 3, m[12])
            a = correct(a, {
                22: 0,
                25: 0,
                26: bit_at(b, 26),
                28: bit_at(b, 28),
                29: 1,
                31: 0
            })
            m[12] = fix1(a, b, c, d, 3, old_val)
            # rule 14
            old_val = d
            d = round1(d, a, b, c, 7, m[13])
            d = correct(d, {
                22: 0,
                25: 0,
                26: 1,
                28: 1,
                29: 0,
                31: 1
            })
            m[13] = fix1(d, a, b, c, 7, old_val)
            # rule 15
            old_val = c
            c = round1(c, d, a, b, 11, m[14])
            c = correct(c, {
                18: bit_at(d, 18),
                22: 1,
                25: 1,
                26: 0,
                28: 0,
                29: 0
            })
            m[14] = fix1(c, d, a, b, 11, old_val)
            # rule 16
            old_val = b
            b = round1(b, c, d, a, 19, m[15])
            b = correct(b, {
                18: 0,
                25: 1,
                26: 1,
                28: 1,
                29: 0
            })
            m[15] = fix1(b, c, d, a, 19, old_val)

            msg1 = struct.pack("<16I", *m)
            # craft the colliding msg
            m[1] = (m[1] + (1 << 31)) % 0x100000000
            m[2] = (m[2] + (1 << 31) - (1 << 28)) % 0x100000000
            m[12] = (m[12] - (1 << 16)) % 0x100000000
            msg2 = struct.pack("<16I", *m)
            if MD4(msg1).hexdigest() == MD4(msg2).hexdigest():
                print('\nFound a collision!')
                print(msg1)
                print(msg2)
                with count.get_lock():
                    print(f'Taken {count.value} trials.')
                    count.value = -1
                break

    # search_thread()
    procs = [Process(target=search_thread) for _ in range(cpu_count())]
    for p in procs:
        p.start()
    for p in procs:
        p.join()

# challenge 56, I'm treating myself
from multiprocessing import Pool
from tqdm import tqdm
from Crypto.Cipher import ARC4
cookie = b64decode('QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F')
def oracle(msg: bytes):
    return ARC4.new(generate_key()).encrypt(msg + cookie)

# Z_16: 240
# Z_32: 224
msglen = len(oracle(b''))
choice = []
for i in range(msglen):
    row = []
    for j in range(256):
        row.append(Value('I', 0))
    choice.append(row)
repeat = 2 ** 15
# padding is from 0 to 31 byte long
def query(padlen):
    encrypted = oracle(b'A' * padlen)
    idx = 15 - padlen
    if 0 <= idx < msglen:
        counter = choice[idx][encrypted[15] ^ 240]
        with counter.get_lock():
            counter.value += 1
    idx = 31 - padlen
    if 0 <= idx < msglen:
        counter = choice[idx][encrypted[31] ^ 224]
        with counter.get_lock():
            counter.value += 1

pool = Pool(cpu_count())
pbar = tqdm(total=32 * repeat)
def update(*a):
    pbar.update()
for padlen in range(32):
    for _ in range(repeat):
        pool.apply_async(query, args=(padlen,), callback=update)
pool.close()
pool.join()

bytes_ = []
for idx in range(msglen):
    curr_max = None
    curr_count = None
    for i in range(256):
        count = choice[idx][i].value
        if curr_count is None or curr_count < count:
            curr_count = count
            curr_max = i
    bytes_.append(curr_max)
print(bytes(bytes_))
print(cookie)
assert cookie == bytes(bytes_)