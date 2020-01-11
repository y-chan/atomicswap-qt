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

from .address import b58_address_to_hash160, hash160_to_b58_address, hash160
from .coind import Coind
from .script import extract_pkccript_addrs, ScriptType
from .transaction import deserialize, deserialize_witness, atomic_swap_extract

import binascii
import time

from datetime import datetime, timedelta
from typing import Tuple


def auditcontract(contract_str: str, contract_tx_str: str, coind: Coind, logging=True) -> Tuple[bool, bytes, float]:
    contract = binascii.a2b_hex(contract_str)
    try:
        contract_tx = deserialize_witness(contract_tx_str, coind)
    except:
        contract_tx = deserialize(contract_tx_str, coind)
    contract_hash160 = hash160(contract)
    contract_out = -1
    for i, tx_out in enumerate(contract_tx.tx_outs):
        sc, addr = extract_pkccript_addrs(tx_out.pkscript, coind)
        if sc != ScriptType.ScriptHash:
            continue
        _, addr_hash = b58_address_to_hash160(addr, coind)
        if addr_hash == contract_hash160:
            contract_out = i
            break
    if contract_out == -1:
        raise Exception("Transaction does not contain the contract output!")
    pushes = atomic_swap_extract(contract)
    contract_addr = hash160_to_b58_address(contract_hash160, coind.p2sh)
    recipient_addr = hash160_to_b58_address(pushes["recipient_addr_hash"], coind.p2pkh)
    refund_addr = hash160_to_b58_address(pushes["refund_addr_hash"], coind.p2pkh)
    now = int(time.mktime(datetime.now().timetuple()))
    locktime = pushes["locktime"]
    dt = datetime.fromtimestamp(locktime)
    reach_bool = locktime >= now
    if logging:
        print("Contract address:", contract_addr)
        print("Contract value:", contract_tx.tx_outs[contract_out].value / 1e8, coind.unit)
        print("Recipient address:", recipient_addr)
        print("Author's refund address:", refund_addr)
        print("Secret hash:", pushes["secret_hash"].hex())
        print("Locktime:", dt)
        if reach_bool:
            reach = timedelta(seconds=locktime-now)
            print("Locktime reached in", reach)
        else:
            print("Contract refund time lock has expired")
    return reach_bool, pushes["secret_hash"], contract_tx.tx_outs[contract_out].value / 1e8
