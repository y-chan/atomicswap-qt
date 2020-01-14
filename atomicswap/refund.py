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

from .coind import Coind
from .contract import buildRefund, calcFeePerKb
from .script import parse_script, mix_script
from .transaction import atomic_swap_extract, deserialize, deserialize_witness, MsgTx
from .util import to_amount, amount_format

import binascii

def refund(contracr_str: str, contract_tx_str: str, coind: Coind) -> MsgTx:
    contract = binascii.a2b_hex(contracr_str)
    try:
        contract_tx = deserialize_witness(contract_tx_str, coind)
    except:
        contract_tx = deserialize(contract_tx_str, coind)
    atomic_swap_extract(contract)
    fee_per_kb, min_fee_per_kb = coind.get_fee_per_byte()
    unparsed_contract = parse_script(contract)
    mixed_contract = mix_script(unparsed_contract)
    refund_tx, refund_fee = buildRefund(mixed_contract, contract_tx,
                                        coind, fee_per_kb, min_fee_per_kb)
    refund_txhash = refund_tx.get_txid()
    refund_fee_per_kb = amount_format(calcFeePerKb(refund_fee, refund_tx.serialize_witness_size()))
    print("Refund fee:", to_amount(refund_fee), coind.unit, "(" + refund_fee_per_kb, coind.unit + "/KB)")
    print("Refund transaction(" + refund_txhash.hex() + ")")
    print(refund_tx.serialize_witness().hex())
    return refund_tx
