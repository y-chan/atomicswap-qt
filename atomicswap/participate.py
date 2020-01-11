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

from .address import is_p2pkh
from .coind import Coind
from .contract import buildContract, contractTuple, calcFeePerKb, builtTuple

import binascii
import time
from datetime import datetime


def participate(addr: str, amount: int, secret_hash: str, coind: Coind) -> builtTuple:
    assert is_p2pkh(addr, coind)
    secret_hash = binascii.a2b_hex(secret_hash)
    locktime = int(time.mktime(datetime.now().timetuple())) + 24 * 60 * 60
    contract = contractTuple(addr, amount, locktime, secret_hash)
    b = buildContract(contract, coind)
    refund_txhash = b.refundTx.get_txid()
    contract_fee_per_kb = "{:.8f}".format(calcFeePerKb(b.contractFee, b.contractTx.serialize_witness_size()))
    refund_fee_per_kb = "{:.8f}".format(calcFeePerKb(b.refundFee, b.refundTx.serialize_witness_size()))
    print("Secret Hash:", secret_hash.hex())
    print("Contract Fee:", b.contractFee / 1e8, coind.unit + "(" + contract_fee_per_kb, coind.unit + "/KB)")
    print("Refund Fee:", b.refundFee / 1e8, coind.unit + "(" + refund_fee_per_kb, coind.unit + "/KB)")
    print("Contract (" + b.contractP2SH + "):")
    print(b.contract.hex())
    print("Contract Transaction (" + b.contractTxHash.hex() + "):")
    print(b.contractTx.serialize_witness().hex())
    print("Refund Transaction (" + refund_txhash.hex() + "):")
    print(b.refundTx.serialize_witness().hex())
    return b
