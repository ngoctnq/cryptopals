from multiprocessing import Value, cpu_count
import numpy as np
from gmac import gmac, GF2p128, Polynomial
from tqdm.auto import trange, tqdm
from utils import generate_key, AES_encrypt
from struct import pack
from joblib import Parallel, delayed

# 2^n number of blocks
n = 17
trunc_size = 8 * 4
cpu_count = cpu_count()

def format_time(sec):
    sec = int(sec)
    hh = sec // 3600
    mm = (sec % 3600) // 60
    ss = sec % 60
    acc = ''
    if hh > 0:
        acc += f'{hh} hour'
        if hh > 1: acc += 's'
        acc += ' '
    if mm > 0:
        acc += f'{mm} minute'
        if mm > 1: acc += 's'
        acc += ' '
    if ss > 0:
        acc += f'{ss} second'
        if ss > 1: acc += 's'
        acc += ' '
    return acc.strip()

def block2gf(block):
    assert len(block) == 16
    return GF2p128(int.from_bytes(block, 'big'))

def gf2vec(val: GF2p128):
    ret = np.empty((128,), dtype=np.int8)
    val = val.val
    for i in range(128):
        ret[i] = val & 1
        val >>= 1
    return ret

sqr_mat = np.empty((128, 128), dtype=np.int8)
for i in range(128):
    sqr_mat[:, i] = gf2vec(GF2p128(1 << i) ** 2)

def gf2mat(val: GF2p128):
    ret = np.empty((128, 128), dtype=np.int8)
    acc = GF2p128(1)
    for i in range(128):
        ret[:, i] = gf2vec(val * acc)
        acc.val <<= 1
    return ret

def vec2gf(vec: np.array):
    ret = 0
    for bit in reversed(vec):
        ret <<= 1
        ret |= int(bit)
    return GF2p128(ret)

def vec2block(vec: np.array):
    ret = 0
    for bit in reversed(vec):
        ret <<= 1
        ret |= int(bit)
    return int.to_bytes(ret, 16, 'big')

def gaussian_nullspace(mat):
    mat = mat.T
    target = np.eye(mat.shape[0], dtype=np.int8)
    idx = 0
    rank = 0
    for idx in trange(mat.shape[1], desc='Calculating the nullspace', leave=False):
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

    # transpose so column combination is easier
    target = target[rank:, :].T
    # remove duplicate vectors
    target = np.unique(target, axis=1)
    # remove zero vector if exists
    target = target[:, np.any(target, axis=0)]
    return target

def get_Ad(blocks):
    # higher order/beginning of blocks first, based on Horner's method
    # remember that this only deals with 2^i-th blocks.
    acc = np.zeros((128, 128), dtype=np.int8)
    if len(blocks.shape) == 1: blocks = np.reshape(blocks, (n, 128))
    for i in range(blocks.shape[0]):
        acc = ((gf2mat(vec2gf(blocks[i,:])) + acc) @ sqr_mat) % 2
    return acc

def get_Ad_loc(i):
    payload = np.zeros((n, 128), dtype=np.int8)
    payload[divmod(i, 128)] = 1
    return get_Ad(payload)

def get_dependency_matrix(no_of_zero_rows, X):
    # rows = bits in Ad*X, col = bits in blocks
    def get_col(bit_idx):
        return (get_Ad_loc(bit_idx)[:no_of_zero_rows, :] @ X).flatten() % 2
    return np.stack(Parallel(n_jobs=cpu_count)(delayed(get_col)(row_idx) for row_idx in trange(n * 128, desc='Fetching dependency matrix', leave=False)), axis=1)

# ```
# [...] [...] [...] [...] [...] size nonce
# 2^n+1  2^n   2^2    3    2^1
#   0     1    ...  2^n-2 2^n-1
# ```

def patch_encrypted(cipher, corrections):
    # assume evenly padded + number of blocks is 2^n
    corrections = np.reshape(corrections, (-1, 128))
    for i in range(n):
        block_idx = 2 ** n + 1 - 2 ** (n - i)
        start_idx = block_idx * 16
        end_idx = start_idx + 16
        cipher = cipher[:start_idx] + \
                 vec2block(gf2vec(block2gf(cipher[start_idx : end_idx])) ^ corrections[i, :]) + \
                 cipher[end_idx:]
    return cipher

found = Value('b')
def set_value(val):
    with found.get_lock(): found.value = val

def try_nullvec(gmac_ok, basis, encrypted, signature):
    while True:
        if found.value: break
        nullvec = (basis @ np.random.randint(2, size=basis.shape[1])) % 2
        if not nullvec.any(): continue
        # remove get_Ad_nullvec
        if gmac_ok(patch_encrypted(encrypted, nullvec), signature):
        # if not ((get_Ad(nullvec)[:trunc_size] @ authkey) % 2).any():
            set_value(1)
            return nullvec