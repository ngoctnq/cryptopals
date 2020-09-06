from chall64_helper import (
    block2gf, gf2vec, gf2mat, vec2gf, vec2block, generate_key, gmac,
    AES_encrypt, pack, cpu_count, np, get_dependency_matrix, trange
)
from random import randrange
from multiprocessing import Pool

def gaussian_elimination(mat):
    mat = mat.T
    target = np.eye(mat.shape[0], dtype=np.int8)
    idx = 0
    rank = 0
    for idx in trange(mat.shape[1], desc='Gaussian Elimination', leave=False):
        if rank == min(mat.shape):
            break
        row_idx = np.flatnonzero(mat[rank:, idx]) + rank
        if len(row_idx) == 0: continue
        if row_idx[0] != rank:
            # swap
            mat[[rank, row_idx[0]]] = mat[[row_idx[0], rank]]
            target[[rank, row_idx[0]]] = target[[row_idx[0], rank]]
        # now subtract from the rest
        for idx_ in row_idx[1:]:
            mat[idx_, :] = (mat[idx_, :] - mat[rank, :]) % 2
            target[idx_, :] = (target[idx_, :] - target[rank, :]) % 2
        rank += 1

    # get the nullspace
    nullspace = target[rank:, :].T
    # remove duplicate vectors
    nullspace = np.unique(nullspace, axis=1)
    # remove zero vector if exists
    nullspace = nullspace[:, np.any(nullspace, axis=0)]
    
    # inverse
    inverse = target[:rank, :].T
    inverse = np.unique(inverse, axis=1)
    inverse = inverse[:, np.any(inverse, axis=0)]
    
    return inverse, nullspace

key = b'harem_enthusiast'
authkey = gf2vec(block2gf(AES_encrypt(key, b'\x00' * 16)))

trunc_size = 8

print('Generating new message...')
msg = generate_key(randrange(3 * 16))
nonce = generate_key(12)
encrypted, signature = gmac(key, msg, b'', nonce)
signature = signature[-trunc_size // 8:]

# pad the message to be full width
lengthened = encrypted + bytes(-len(msg) % 16)
lengthened = bytes(3 * 16 - len(lengthened)) + lengthened

t = (gf2mat(pack('>2Q', 0, len(encrypted))) - gf2mat(pack('>2Q', 0, len(lengthened)))).flatten() % 2

# accumulator through the iterations
X = np.eye(128, dtype=np.int8)
pool = Pool(cpu_count)
no_of_zero_rows = min(2 * 128 // X.shape[1], trunc_size)
dependency = get_dependency_matrix(no_of_zero_rows, X)
inverse, nullspace = gaussian_elimination(dependency)
print(dependency.shape)