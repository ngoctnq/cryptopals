# all of this code will work with rationals
from typing import List
from fractions import Fraction
Vector = List[Fraction]

def add(v1: Vector, v2: Vector) -> Vector:
    assert len(v1) == len(v2), "Cannot add vectors of different dimensions!"
    return [x1 + x2 for (x1, x2) in zip(v1, v2)]

def sub(v1: Vector, v2: Vector) -> Vector:
    assert len(v1) == len(v2), "Cannot subtract vectors of different dimensions!"
    return [x1 - x2 for (x1, x2) in zip(v1, v2)]

def dot(v1: Vector, v2: Vector) -> Fraction:
    assert len(v1) == len(v2), "Cannot dot product vectors of different dimensions!"
    return sum([x1 * x2 for (x1, x2) in zip(v1, v2)])

def l2_sqr(v: Vector) -> Fraction:
    return dot(v, v)

def scale(v: Vector, s: Fraction) -> Vector:
    return [x * s for x in v]

def project(v1: Vector, v2: Vector) -> Vector:
    '''
    Project v1 upon v2.
    '''
    assert len(v1) == len(v2), "Cannot project vectors of different dimensions!"
    l22v2 = l2_sqr(v2)
    if l22v2 == 0: return [Fraction(0)] * len(v1)
    return scale(v2, dot(v1, v2) / l22v2)

def gram_schmidt(basis: List[Vector]) -> List[Vector]:
    new_basis = []
    for i, vec in enumerate(basis):
        for k in range(i):
            vec = sub(vec, project(vec, new_basis[k]))
        new_basis.append(vec)
    return new_basis

def LLL(basis, delta=0.99):
    '''
    Lenstra-Lenstra-Lovasz to reduce a basis
    '''
    basis = basis[:]
    ortho = gram_schmidt(basis)

    def mu(i, j):
        v = basis[i]
        u = ortho[j]
        return dot(u, v) / dot(u, u)

    n = len(basis)
    k = 1

    while k < n:
        for j in reversed(range(k)):
            if abs(mu(k, j)) > 1 / 2:
                basis[k] = dot(sub(basis[k], round(mu(k, j))), basis[j])
                ortho = gram_schmidt(basis)

        if l2_sqr(ortho[k]) >= (delta - mu(k, k - 1) ** 2) * l2_sqr(ortho[k-1]):
            k = k + 1
        else:
            basis[k], basis[k - 1] = basis[k - 1], basis[k]
            ortho = gram_schmidt(basis)
            k = max(k - 1, 1)

    return basis