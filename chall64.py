from multiprocessing import Pool
from time import time
from chall64_helper import (
    generate_key,
    AES_encrypt,
    GF2p128,
    gf2vec,
    block2gf,
    gmac,
    np,
    n,
    cpu_count,
    pack,
    get_Ad,
    get_dependency_matrix,
    gaussian_nullspace,
    set_value,
    try_nullvec
)

# accumulator through the iterations
X = np.eye(128, dtype=np.int8)

key = b'harem_enthusiast'
authkey = gf2vec(block2gf(AES_encrypt(key, b'\x00' * 16)))
msg = generate_key(2 ** n * 16 - 8)
nonce = generate_key(12)
encrypted, signature = gmac(key, msg, b'', nonce)
# get the last 32 bit
trunc_size = 8 * 4
signature = signature[-trunc_size // 8:]
assert len(encrypted) == 2 ** n * 16

def gmac_ok(cipher, mac):
    authkey = AES_encrypt(key, b'\x00' * 16)
    authkey = GF2p128(int.from_bytes(authkey, 'big'))
    content = cipher + b'\x00' * (-len(cipher) % 16) + pack('>2Q', 0, len(cipher))
    g = GF2p128(0)
    for i in range(0, len(content), 16):
        b = GF2p128(int.from_bytes(content[i : i + 16], 'big'))
        g += b
        g *= authkey
    s = AES_encrypt(key, nonce + b'\x00\x00\x00\x01')
    s = GF2p128(int.from_bytes(s, 'big'))
    g += s
        
    return int.to_bytes(g.val, 16, 'big')[-trunc_size // 8:] == mac

pool = Pool(cpu_count)
while X.shape[1] > 1:
    print(X.shape[1], 'basis vectors left.')
    no_of_zero_rows = min(n * 128 // X.shape[1] - 1, trunc_size - 1)
    print('Zeroing out', no_of_zero_rows, 'rows.')
    dependency = get_dependency_matrix(no_of_zero_rows, X)
    nullspace = gaussian_nullspace(dependency)

    print('Rolling the dice until dawn...')
    set_value(0)
    tic = time()
    nullvec = pool.starmap(
        try_nullvec,
        [(gmac_ok, nullspace, encrypted, signature)] * cpu_count
    )
    toc = time()
    print('That took', int(toc - tic), 'seconds.')
    for i in nullvec:
        if i is not None:
            nullvec = i
            break

    new_nullspace = (get_Ad(nullvec)[no_of_zero_rows:trunc_size] @ X) % 2
    new_domain = gaussian_nullspace(new_nullspace)
    X = (X @ new_domain) % 2

assert authkey == X.T
print('\n[!] Authentication key recovered successfully!\n')

