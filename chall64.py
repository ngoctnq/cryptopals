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
    trunc_size,
    pack,
    get_Ad,
    get_dependency_matrix,
    gaussian_nullspace,
    set_value,
    try_nullvec,
    format_time
)

key = b'harem_enthusiast'
authkey = gf2vec(block2gf(AES_encrypt(key, b'\x00' * 16)))

# accumulator through the iterations
X = np.eye(128, dtype=np.int8)
pool = Pool(cpu_count)

while X.shape[1] > 1:
    print('[+]', X.shape[1], 'basis vectors left.')

    print('Generating new message...')
    msg = generate_key(2 ** n * 16 - 8)
    nonce = generate_key(12)
    encrypted, signature = gmac(key, msg, b'', nonce)
    # get the last 32 bit
    signature = signature[-trunc_size // 8:]
    assert len(encrypted) == 2 ** n * 16

    no_of_zero_rows = min(n * 128 // X.shape[1], trunc_size) - 1
    print('Zeroing out', no_of_zero_rows, 'rows.')
    dependency = get_dependency_matrix(no_of_zero_rows, X)
    nullspace = gaussian_nullspace(dependency)

    print('Rolling the dice until dawn...')
    set_value(0)
    tic = time()
    nullvec = pool.starmap(
        try_nullvec,
        [(nullspace, encrypted, key, signature, nonce)] * cpu_count
    )
    toc = time()
    print('That took', format_time(toc - tic))
    for i in nullvec:
        if i is not None:
            nullvec = i
            break

    new_nullspace = (get_Ad(nullvec)[no_of_zero_rows:trunc_size] @ X) % 2
    new_domain = gaussian_nullspace(new_nullspace)
    X = (X @ new_domain) % 2

assert (authkey == X.T).all()
print('\n[!] Authentication key recovered successfully!\n')

