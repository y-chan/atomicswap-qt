# Copyright (c) 2010-2020 The Go Authors
# Copyright (c) 2014-2020 The btcsuite developers
# Copyright (c) 2019-2020 The atomicswap-qt developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from enum import IntEnum
from hashlib import sha256
from typing import Tuple

import hmac


class secp256k1(IntEnum):
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    b = 0x0000000000000000000000000000000000000000000000000000000000000007
    gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    bitsize = 256
    q = (p + 1) // 4
    h = 1
    half_order = n >> 1


class Signature:
    def __init__(self, r: int, s: int):
        self.r = r
        self.s = s

    def signature_serialize(self) -> bytes:
        sig_s = self.s
        if sig_s > secp256k1.half_order:
            sig_s = secp256k1.n - sig_s
        rb = canonicalize_int(self.r)
        sb = canonicalize_int(sig_s)

        length = 6 + len(rb) + len(sb)
        b = (0x30).to_bytes(1, 'big')
        b += (length - 2).to_bytes(1, 'big')
        b += (0x02).to_bytes(1, 'big')
        b += (len(rb)).to_bytes(1, 'big')
        b += rb
        b += (0x02).to_bytes(1, 'big')
        b += (len(sb)).to_bytes(1, 'big')
        b += sb
        return b

def canonicalize_int(val: int) -> bytes:
    try:
        b = val.to_bytes(len(hex(val)[2:]) // 2, 'big')
    except:
        b = val.to_bytes(len(hex(val)) // 2, 'big')
    if len(b) == 0:
        b = bytes(1)
    if b[0] & 0x80 != 0:
        b = bytes(1) + b
    return b


def sign_rfc6979(priv_key: int, in_hash: bytes) -> Signature:
    n = secp256k1.n
    half_order = secp256k1.half_order
    k = nonce_rfc6979(priv_key, in_hash)
    inv = mod_inv(k, n)
    try:
        k_bytes = k.to_bytes(len(hex(k)[2:]), 'big')
    except:
        k_bytes = k.to_bytes(len(hex(k)), 'big')
    r, _ = scalar_base_mult(k_bytes)
    r %= n

    if r == 0:
        raise Exception("Calculated R is zero!")
    e = hash_to_int(in_hash)
    s = ((priv_key * r + e) * inv) % n
    if s > half_order:
        s = n - s
    if s == 0:
        raise Exception("Calculated S is zero!")
    return Signature(r, s)


# https://tools.ietf.org/html/rfc6979#section-3.2
def nonce_rfc6979(priv_key: int, in_hash: bytes) -> int:
    q = secp256k1.n
    x = priv_key
    alg = sha256
    qlen = q.bit_length()
    holen = alg().digest_size
    rolen = (qlen + 7) >> 3
    bx = [int2octets(x, rolen), bits2octets(in_hash, rolen)]

    # Step B
    v = b'\x01' * holen

    # Step C
    k = b'\x00' * holen

    # Step D
    k = hmac.new(k, digestmod=alg)
    k.update(v + b'\x00')
    for i in bx:
        k.update(i)
    k = k.digest()

    # Step E
    v = hmac.new(k, v, alg).digest()

    # Step F
    k = hmac.new(k, digestmod=alg)
    k.update(v + b'\x01')
    for i in bx:
        k.update(i)
    k = k.digest()

    # Step G
    v = hmac.new(k, v, alg).digest()

    # Step H
    while True:
        # Step H1
        t = b''

        # Step H2
        while len(t) < rolen:
            v = hmac.new(k, v, alg).digest()
            t += v

        # Step H3
        secret = hash_to_int(t)

        if 1 <= secret < q:
            return secret
        k = hmac.new(k, v + b'\x00', alg).digest()
        v = hmac.new(k, v, alg).digest()


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def mod_inv(a: int, m: int):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def hash_to_int(v: bytes) -> int:
    order_bytes = (secp256k1.bitsize + 7) // 8
    if len(v) > order_bytes:
        v = v[:order_bytes]
    ret = int.from_bytes(v, 'big')
    excess = len(v) * 8 - secp256k1.bitsize
    if excess > 0:
        ret = ret >> excess
    return ret


# https://tools.ietf.org/html/rfc6979#section-2.3.3
def int2octets(v: int, rolen: int) -> bytes:
    v_len = len(hex(v)[2:]) // 2
    try:
        out = v.to_bytes(v_len, 'big')
    except:
        out = v.to_bytes(v_len + 1, 'big')

    if len(out) < rolen:
        out2 = bytes(rolen - len(out))
        out2 += out
        return out2

    if len(out) > rolen:
        out2 = out[len(out) - rolen:]
        return out2
    return out


# https://tools.ietf.org/html/rfc6979#section-2.3.4
def bits2octets(v: bytes, rolen: int) -> bytes:
    z1 = hash_to_int(v)
    z2 = z1 - secp256k1.n
    if z2 < 0:
        return int2octets(z1, rolen)
    return int2octets(z2, rolen)


def scalar_base_mult(k: bytes) -> Tuple[int, int]:
    bx = secp256k1.gx
    by = secp256k1.gy
    bz = 1
    x, y, z = 0, 0, 0
    for _, byte in enumerate(k):
        for num in range(8):
            x, y, z = double_jacobian(x, y, z)
            if byte & 0x80 == 0x80:
                x, y, z = add_jacobian(bx, by, bz, x, y, z)
            byte = byte << 1
    return affine_from_jacobian(x, y, z)


def add_jacobian(x1: int, y1: int, z1: int, x2: int, y2: int, z2: int) -> Tuple[int, int, int]:
    x3, y3, z3 = 0, 0, 0
    if z1 == 0:
        return x2, y2, z2
    if z2 == 0:
        return x1, y1, z1
    z1z1 = (z1 ** 2) % secp256k1.p
    z2z2 = (z2 ** 2) % secp256k1.p

    u1 = (x1 * z2z2) % secp256k1.p
    u2 = (x2 * z1z1) % secp256k1.p
    h = u2 - u1
    x_equal = h == 0
    if h < 0:
        h += secp256k1.p
    i = (h << 1) ** 2
    j = h * i

    s1 = (y1 * z2 * z2z2) % secp256k1.p
    s2 = (y2 * z1 * z1z1) % secp256k1.p
    r = s2 - s1
    if r < 0:
        r += secp256k1.p
    y_equal = r == 0
    if x_equal and y_equal:
        return double_jacobian(x1, x2, x3)
    r = r << 1
    v = u1 * i

    x3 = (r ** 2 - (j + v * 2)) % secp256k1.p

    v -= x3
    s1 = (s1 * j) << 1
    y3 = (r * v - s1) % secp256k1.p

    z3 = (((z1 + z2) ** 2 - (z1z1 + z2z2)) * h) % secp256k1.p
    return x3, y3, z3


def double_jacobian(x: int, y: int, z: int) -> Tuple[int, int, int]:
    a = x ** 2
    b = y ** 2
    c = b ** 2
    d = ((x + b) ** 2 - (a + c)) * 2
    e = 3 * a
    f = e ** 2

    x3 = (f - (2 * d)) % secp256k1.p
    y3 = (e * (d - x3) - (8 * c)) % secp256k1.p
    z3 = (y * z * 2) % secp256k1.p
    return x3, y3, z3


def affine_from_jacobian(x: int, y: int, z: int) -> Tuple[int, int]:
    if z == 0:
        return 0, 0
    z_inv = mod_inv(z, secp256k1.p)
    z_inv_sq = z_inv ** 2

    x_out = (x * z_inv_sq) % secp256k1.p
    z_inv_sq = z_inv_sq * z_inv
    y_out = (y * z_inv_sq) % secp256k1.p
    return x_out, y_out


def pubkey_from_privkey(privkey: bytes) -> bytes:
    x, y = scalar_base_mult(privkey)
    _format = 0x2
    bit = y >> 0 & 1
    if bit == 1:
        _format |= 0x1
    b = _format.to_bytes(1, 'big')
    try:
        x_len = len(hex(x)[2:]) // 2
        x_bytes = x.to_bytes(x_len, 'big')
    except:
        x_len = len(hex(x)) // 2
        x_bytes = x.to_bytes(x_len, 'big')
    for i in range(32 - x_len):
        b += (0).to_bytes(1, 'big')
    return b + x_bytes
