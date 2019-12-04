# -*- coding: utf-8 -*-
# Copyright (c) 2011-2019 The Electrum Developers
# Copyright (c) 2014-2019 The btcsuite developers
# Copyright (c) 2019 The atomicswap-qt developers
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

from typing import Union, Tuple, Optional

import hashlib

from .coind import Coind

__b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(__b58chars) == 58

__b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
assert len(__b43chars) == 43


class PrivkeyDecodeError(Exception): pass


def assert_bytes(*args):
    """
    porting helper, assert args type
    """
    try:
        for x in args:
            assert isinstance(x, (bytes, bytearray))
    except:
        print('assert bytes failed', list(map(type, args)))
        raise


def base_encode(v: bytes, base: int) -> str:
    """ encode v, which is a string of bytes, to base58."""
    assert_bytes(v)
    if base not in (58, 43):
        raise ValueError('not supported base: {}'.format(base))
    chars = __b58chars
    if base == 43:
        chars = __b43chars
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += (256 ** i) * c
    result = bytearray()
    while long_value >= base:
        div, mod = divmod(long_value, base)
        result.append(chars[mod])
        long_value = div
    result.append(chars[long_value])
    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == 0x00:
            nPad += 1
        else:
            break
    result.extend([chars[0]] * nPad)
    result.reverse()
    return result.decode('ascii')


def base_decode(v: Union[bytes, str], length: Optional[int], base: int) -> Optional[bytes]:
    """ decode v into a string of len bytes."""
    # assert_bytes(v)
    v = to_bytes(v, 'ascii')
    if base not in (58, 43):
        raise ValueError('not supported base: {}'.format(base))
    chars = __b58chars
    if base == 43:
        chars = __b43chars
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        digit = chars.find(bytes([c]))
        if digit == -1:
            raise ValueError('Forbidden character {} for base {}'.format(c, base))
        long_value += digit * (base ** i)
    result = bytearray()
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result.append(mod)
        long_value = div
    result.append(long_value)
    nPad = 0
    for c in v:
        if c == chars[0]:
            nPad += 1
        else:
            break
    result.extend(b'\x00' * nPad)
    if length is not None and len(result) != length:
        return None
    result.reverse()
    return bytes(result)


def to_bytes(something, encoding='utf8') -> bytes:
    """
    cast string to bytes() like object, but for python2 support it's bytearray copy
    """
    if isinstance(something, bytes):
        return something
    if isinstance(something, str):
        return something.encode(encoding)
    elif isinstance(something, bytearray):
        return bytes(something)
    else:
        raise TypeError("Not a string or bytes like object")


def b58_address_to_hash160(addr: str, coind: Coind) -> Tuple[bytes, bytes]:
    addr = to_bytes(addr, 'ascii')
    if isinstance(coind.p2pkh, list):
        _bytes = base_decode(addr, 26, base=58)
        return _bytes[0:2], _bytes[2:22]
    _bytes = base_decode(addr, 25, base=58)
    return _bytes[0:1], _bytes[1:21]


def is_p2pkh(addr: str, coind: Coind) -> bool:
    try:
        addrtype, h = b58_address_to_hash160(addr, coind)
    except:
        return False
    if isinstance(coind.p2pkh, list) and addrtype != bytes(coind.p2pkh):
        return False
    elif isinstance(coind.p2pkh, int) and addrtype != bytes([coind.p2pkh]):
        return False
    return addr == hash160_to_b58_address(h, coind.p2pkh)


def sha256(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, 'utf8')
    return bytes(hashlib.sha256(x).digest())


def sha256d(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, 'utf8')
    out = bytes(sha256(sha256(x)))
    return out


def hash160_to_b58_address(h160: bytes, addrtype: Union[int, list]) -> str:
    if isinstance(addrtype, list):
        s = bytes(addrtype) + h160
    else:
        s = bytes([addrtype]) + h160
    s = s + sha256d(s)[0:4]
    return base_encode(s, base=58)


def hash160(x: Union[bytes, str]) -> bytes:
    x = to_bytes(x, 'utf8')
    h160 = hashlib.new('ripemd160')
    h160.update(sha256(x))
    out = h160.digest()
    return bytes(out)


def b58_privkey_to_hash160(privkey: str) -> Tuple[bytes, bytes]:
    key = to_bytes(privkey, 'ascii')
    try:
        _bytes = base_decode(key, 38, base=58)
        if _bytes is None or _bytes[33] != 0x01:
            raise
    except:
        _bytes = base_decode(key, 37, base=58)
        if _bytes is None:
            raise PrivkeyDecodeError("Privkey doesn't decode!")
    to_sum = _bytes[:-4]
    ck_sum = sha256d(to_sum)[:4]
    if ck_sum != _bytes[-4:]:
        raise PrivkeyDecodeError("CheckSum isn't mutch!")
    return _bytes[0:1], _bytes[1:33]
