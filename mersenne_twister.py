# reimplementation of MT19937 based on Wiki pseudocode
w, n, m, r = 32, 624, 397, 31
a = 0x9908B0DF
u = 11
s, b = 7, 0x9D2C5680
t, c = 15, 0xEFC60000
l = 18
f = 1812433253

# Create a length n array to store the state of the generator
lower_mask = 0x7fffffff
upper_mask = 0x80000000


def seed_mt(seed: int):
    # Initialize the generator from a seed
    states = [0] * n
    states[0] = seed
    for i in range(1, n): # loop over each element
        states[i] = (f * (states[i - 1] ^ (states[i - 1] >> (w - 2))) + i) & ((1 << w) - 1)

    global generator
    generator = create_generator(states)


def twist(states):
    # Generate the next n values from the series x_i 
    for i in range(n):
        x = (states[i] & upper_mask) + (states[(i + 1) % n] & lower_mask)
        xA = x >> 1
        if x % 2 != 0:
            # lowest bit of x is 1
            xA ^= a
        states[i] = states[(i + m) % n] ^ xA


def create_generator(states):
    # Extract a tempered value based on MT[index]
    # calling twist() every n numbers
    i = 0
    while True:
        if i == 0: twist(states)

        y = states[i]
        y ^= (y >> u)
        y ^= ((y << s) & b)
        y ^= ((y << t) & c)
        y ^= (y >> l)

        i = (i + 1) % n

        yield y & ((1 << w) - 1)


# default seed
seed_mt(5489)
def get_random_number():
    return next(generator)

# this is to reverse tempering outputs
def undo_xor_shift(y: int, l: int) -> int:
    # reverse y ^= (y >> l)
    original = y
    while True:
        candidate = y ^ (y >> l)
        if candidate == original:
            return y
        else:
            y = candidate

def undo_xor_shift_and(y: int, s: int, b: int) -> int:
    # reverse y ^= ((y << s) & b)
    original = y
    y = 0
    while True:
        y = (original ^ ((y << s) & b))
        if y ^ ((y << s) & b) == original:
            return y

def untemper(y: int) -> int:
    y = undo_xor_shift(y, l)
    y = undo_xor_shift_and(y, t, c)
    y = undo_xor_shift_and(y, s, b)
    y = undo_xor_shift(y, u)
    return y