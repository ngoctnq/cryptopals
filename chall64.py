import numpy as np
from gmac import gmac, GF2p128, Polynomial
from tqdm import trange
from utils import generate_key, AES_encrypt
from struct import pack
from random import seed

# for reproducibility
seed(123)
np.random.seed(456)

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

def gaussian_nullspace(mat):
    mat = mat.T
    target = np.eye(mat.shape[0], dtype=np.int8)
    idx = 0
    rank = 0
    while True:
        if idx == mat.shape[1] or rank == min(mat.shape):
            break
        row_idx = np.flatnonzero(mat[rank:, idx]) + rank
        idx += 1
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


test = block2gf(b"One day I'm gon'")
assert (gf2vec(test ** 2) == (sqr_mat @ gf2vec(test)) % 2).all()
test2 = block2gf(b'marry a pornstar')
assert (gf2vec(test * test2) == (gf2mat(test2) @ gf2vec(test)) % 2).all()
assert (gf2vec(test * test2) == (gf2mat(test) @ gf2vec(test2)) % 2).all()
assert (gf2vec(test ** 16) == (np.linalg.matrix_power(sqr_mat, 4) @ gf2vec(test)) % 2).all()
assert (gf2vec(test2 ** 8) == (sqr_mat @ sqr_mat @ sqr_mat @ gf2vec(test2)) % 2).all()

def get_Ad(blocks):
    # higher order/beginning of blocks first, based on Horner's method
    # remember that this only deals with 2^i-th blocks.
    acc = np.zeros((128, 128), dtype=np.int8)
    for block in blocks:
        acc = ((gf2mat(block2gf(block)) + acc) @ sqr_mat) % 2
    return (acc @ sqr_mat) % 2

def get_Ad_loc(i):
    block_idx = i // 128
    cell_idx = i % 128
    byte_idx = cell_idx // 8
    bit_idx = cell_idx % 8
    payload = [bytes(16)] * (1 + block_idx) + \
                [bytes(byte_idx) + bytes([1 << bit_idx]) + bytes(15 - byte_idx)] + \
                [bytes(16)] * (127 - block_idx)
    return get_Ad(payload)

def gmac_ok(key, cipher, mac, nonce):
    '''
    Input:
        @key:       key to be encrypted/GMAC
        @cipher:    cipher to be decrypted
        @mac:       the generated MAC to be checked
        @nonce:     96-bit of nonce to XOR at the end
    '''
    authkey = AES_encrypt(key, b'\x00' * 16)
    authkey = GF2p128(int.from_bytes(authkey, 'big'))
    if len(cipher) == 0:
        iv = encrypted = b''
    else:
        iv = cipher[:8]
        encrypted = cipher[8:]
    content = iv + encrypted + b'\x00' * (-len(iv + encrypted) % 16) + \
              pack('>2Q', 0, len(iv + encrypted))
    g = GF2p128(0)
    for i in range(0, len(content), 16):
        b = GF2p128(int.from_bytes(content[i : i + 16], 'big'))
        g += b
        g *= authkey
    s = AES_encrypt(key, nonce + b'\x00\x00\x00\x01')
    s = GF2p128(int.from_bytes(s, 'big'))
    g += s
    return int.to_bytes(g.val, 16, 'big').startswith(mac)

n = 16
# accumulator through the iterations
X = np.eye(128)
Ad_0 = get_Ad([b'\x00' * 16] * n)

from joblib import Parallel, delayed
def get_dependency_matrix():
    # rows = bits in Ad*X, col = bits in blocks
    Ad0_ = Ad_0 @ X
    no_of_zero_rows = n * 128 // X.shape[1] - 1
    def get_col(bit_idx):
        return ((get_Ad_loc(bit_idx) @ X)[:no_of_zero_rows, :] != Ad0_[:no_of_zero_rows, :]).astype(np.int8).flatten()
    return np.stack(Parallel(n_jobs=8)(delayed(get_col)(row_idx) for row_idx in trange(n * 128)), axis=1)

print(get_dependency_matrix())
