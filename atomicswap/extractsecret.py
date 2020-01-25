# Copyright (c) 2015-2020 The Decred developers
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

from .address import sha256
from .contract import secretSize
from .coind import Coind
from .script import parse_script
from .transaction import deserialize, deserialize_witness

import binascii


def extractsecret(redeem_tx_str: str, secret_hash_str: str, coind: Coind, logging=True) -> bytes:
    try:
        redeem_tx = deserialize_witness(redeem_tx_str, coind)
    except:
        redeem_tx = deserialize(redeem_tx_str, coind)
    secret_hash = binascii.a2b_hex(secret_hash_str)
    assert len(secret_hash) == secretSize, "SecretHash is miss!"
    for tx_in in redeem_tx.tx_ins:
        pushed = parse_script(tx_in.sig_script)
        data = pushed["data"]
        for sig in data:
            if sha256(sig) == secret_hash:
                if logging:
                    print(extractsecret_print(sig.hex()))
                return sig
    raise Exception("Tx doesn't contain secret!")


def extractsecret_print(sig: str) -> str:
    result = "Secret: " + sig
    return result
