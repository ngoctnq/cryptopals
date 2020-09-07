from chall64_helper import (
    block2gf, gf2vec, gf2mat, vec2gf, vec2block, generate_key, gmac,
    AES_encrypt, pack, cpu_count, np, get_dependency_matrix, n, trunc_size,
    get_Ad, gmac_ok, patch_encrypted
)
from random import randrange
from multiprocessing import Pool
from bisect import bisect

key = b'harem_enthusiast'
authkey = gf2vec(block2gf(AES_encrypt(key, b'\x00' * 16)))
block_count = 2 ** n - 1
pool = Pool(cpu_count)

def gaussian_elimination(mat_):
    mat = mat_.copy().T
    target = np.eye(mat.shape[0], dtype=np.int8)
    idx = 0
    rank = 0

    for idx in range(mat.shape[1]):
        if rank == min(mat.shape):
            break
        row_idx = np.flatnonzero(mat[:, idx])
        if (row_idx < rank).all(): continue
        if rank not in row_idx:
            rank_idx = bisect(row_idx, rank)
            # swap
            mat[[rank, row_idx[rank_idx]]] = mat[[row_idx[rank_idx], rank]]
            target[[rank, row_idx[rank_idx]]] = target[[row_idx[rank_idx], rank]]
            row_idx[rank_idx] = rank
        # now subtract from the rest
        for idx_ in row_idx:
            if idx_ == rank: continue
            mat[idx_, :] = (mat[idx_, :] - mat[rank, :]) % 2
            target[idx_, :] = (target[idx_, :] - target[rank, :]) % 2
        rank += 1

    # get the nullspace
    nullspace = target[rank:, :].T
    # remove duplicate vectors
    if nullspace.size > 0:
        # remove zero vector if exists
        nullspace = nullspace[:, np.any(nullspace, axis=0)]
    
    # inverse
    inverse = target[:rank, :].T
    inverse = inverse[:, np.any(inverse, axis=0)]
    
    return inverse, nullspace

# authkey space
X = np.eye(128, dtype=np.int8)

while X.shape[1] > 1:
    # capture a new packet
    msg = generate_key(randrange(block_count * 16 - 8))
    nonce = generate_key(12)
    encrypted, signature = gmac(key, msg, b'', nonce)
    signature = signature[-trunc_size // 8:]

    # pad the message to be full width
    lengthened = encrypted + bytes(-len(encrypted) % 16)
    lengthened = bytes(block_count * 16 - len(lengthened)) + lengthened

    t = (gf2mat(block2gf(pack('>2Q', 0, len(encrypted)))) - gf2mat(block2gf(pack('>2Q', 0, len(lengthened))))) % 2

    no_of_zero_rows = min(n * 128 // X.shape[1], trunc_size - 1)
    print(X.shape[1], 'basis vectors left, forcing', no_of_zero_rows, 'rows.')
    
    dependency = get_dependency_matrix(no_of_zero_rows, X)

    inverse, nullspace = gaussian_elimination(dependency)
    bitflips = (inverse @ (t[:no_of_zero_rows] @ X).flatten()[:inverse.shape[1]] % 2) % 2
    if nullspace.size == 0:
        print('Empty nullspace!')
        maxtry = 1
    else:
        maxtry = 1024
    found = False
    while maxtry:
        if gmac_ok(key, patch_encrypted(lengthened, bitflips), signature, nonce):
            found = True
            break
        coeff = np.random.randint(2, size=nullspace.shape[1])
        bitflips = (bitflips + nullspace @ coeff) % 2
        maxtry -= 1
    # if not success, try with a new packet
    if not found: continue
    
    new_nullspace = ((get_Ad(bitflips) + t)[no_of_zero_rows:trunc_size] @ X) % 2
    _, new_domain = gaussian_elimination(new_nullspace)
    X = (X @ new_domain) % 2
    
assert (X.T == authkey).all()
print('OK')