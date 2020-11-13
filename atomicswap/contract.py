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

from typing import NamedTuple, Tuple, Union

from .util import to_amount, to_satoshis
from .address import b58_address_to_hash160, hash160_to_b58_address, hash160, sha256d, b58_privkey_to_hash160
from .coind import Coind
from .ecdsa import sign_rfc6979, pubkey_from_privkey
from .opcodes import Opcodes, remove_opcode
from .script import pay_to_addr_script, parse_script, unparse_script
from .transaction import (OutPoint, TxIn, TxOut, MsgTx, int_to_bytes, deserialize_witness,
                          input_size, atomic_swap_extract, ver_int_serialize_size,
                          sum_output_serialize_sizes, is_dust_output, fee_for_serialize_size)

verify = True
secretSize = 32
redeemAtomicSwapSigScriptSize = 1 + 73 + 1 + 33 + 1 + 32 + 1
refundAtomicSwapSigScriptSize = 1 + 73 + 1 + 33 + 1

SigHashOld = 0x0
SigHashAll = 0x1
SigHashNone = 0x2
SigHashSingle = 0x3
SigHashAnyOneCanPay = 0x80
sigHashMask = 0x1f


class BuildContractError(Exception):
    pass


class contract_tuple(NamedTuple):
    to_addr: str
    amount: int
    locktime: int
    secret_hash: bytes


class built_tuple(NamedTuple):
    contract: bytes
    contractP2SH: str
    contractTxHash: bytes
    contractTx: MsgTx
    contractFee: int
    refundTx: MsgTx
    refundFee: int


def build_contract(contract: contract_tuple, coind: Coind) -> built_tuple:
    refund_addr = coind.getrawchangeaddress()
    _, refund_addr_bytes = b58_address_to_hash160(refund_addr, coind)
    _, to_addr_bytes = b58_address_to_hash160(contract.to_addr, coind)
    atomic_swap = atomic_swap_contract(refund_addr_bytes, to_addr_bytes, contract.locktime, contract.secret_hash)
    contract_bytes = unparse_script(atomic_swap)
    contract_hash160 = hash160(contract_bytes)
    p2sh_addr = hash160_to_b58_address(contract_hash160, coind.p2sh)
    p2sh_script = pay_to_addr_script(p2sh_addr, coind)
    script_bytes = unparse_script(p2sh_script)
    fee_per_kb, min_fee_per_kb = coind.get_fee_per_byte()
    new_output = TxOut(contract.amount, script_bytes)
    if coind.ver_id:
        expiry_height = coind.getblockcount() + 20
    else:
        expiry_height = 0
    unsigned_contract = MsgTx(coind, [], new_output, 0, expiry_height)
    fund_hex = unsigned_contract.serialize().hex()
    fund_fee = to_amount(fee_per_kb, coind.decimals)
    fund_result = coind.fundrawtransaction(fund_hex, fund_fee)
    funded_contract = fund_result["hex"]
    contract_fee = to_satoshis(fund_result["fee"], coind.decimals)
    signed_contract = coind.signrawtransaction(funded_contract)["hex"]
    contract_tx = deserialize_witness(signed_contract, coind)
    contract_txhash = contract_tx.get_txid()
    refund_tx, refund_fee = build_refund(atomic_swap, contract_tx,
                                         coind, fee_per_kb, min_fee_per_kb)
    return built_tuple(contract_bytes, p2sh_addr, contract_txhash, contract_tx,
                       contract_fee, refund_tx, refund_fee)


def build_refund(contract: Union[list, bytes], contract_tx: MsgTx, coind: Coind,
                 fee_per_kb: int, min_fee_per_kb: int) -> Tuple[MsgTx, int]:
    if isinstance(contract, bytes):
        contract_bytes = contract
    else:
        contract_bytes = unparse_script(contract)
    contract_hash160 = hash160(contract_bytes)
    p2sh_addr = hash160_to_b58_address(contract_hash160, coind.p2sh)
    p2sh_script = pay_to_addr_script(p2sh_addr, coind)
    p2sh_script_bytes = unparse_script(p2sh_script)
    contract_hash = contract_tx.get_txid()[::-1]
    i = 0
    for tx_out in contract_tx.tx_outs:
        if tx_out.pkscript == p2sh_script_bytes:
            break
        i += 1
    if len(contract_tx.tx_outs) <= i:
        raise BuildContractError("Contract tx hasn't contract!")
    contract_outpoint = OutPoint(contract_hash, i)
    refund_address = coind.getrawchangeaddress()
    refund_script = pay_to_addr_script(refund_address, coind)
    refund_script_bytes = unparse_script(refund_script)
    pushes = atomic_swap_extract(contract)
    refund_addr = hash160_to_b58_address(pushes["refund_addr_hash"], coind.p2pkh)
    if coind.ver_id:
        expiry_height = coind.getblockcount() + 10000
    else:
        expiry_height = 0
    refund_tx = MsgTx(coind, [], [], pushes["locktime"], expiry_height)
    tx_out = TxOut(0, refund_script_bytes)
    refund_size = estimate_refund_serialize_size(contract, [tx_out])
    refund_fee = fee_for_serialize_size(fee_per_kb, refund_size)
    value = contract_tx.tx_outs[i].value - refund_fee
    tx_out.change_params(value=value)
    if is_dust_output(tx_out, min_fee_per_kb):
        raise BuildContractError("refund output value of {} is dust".format(value))
    tx_in = TxIn(contract_outpoint, b"", [], 0)
    refund_tx.change_params(tx_in=tx_in, tx_out=tx_out)
    refund_sig, refund_pubkey = create_sig(refund_tx, 0, contract_bytes, refund_addr, coind)
    refund_sig_script = unparse_script(refund_p2sh_contract(contract_bytes, refund_sig, refund_pubkey))
    tx_ins = []
    for i, tx_in in enumerate(refund_tx.tx_ins):
        if i == 0:
            tx_in.change_params(sig_script=refund_sig_script)
        tx_ins.append(tx_in)
    refund_tx.change_params(tx_in=tx_ins)

    if verify:
        pass
    return refund_tx, refund_fee


def atomic_swap_contract(my_addr_bytes: bytes, to_addr_bytes: bytes, locktime: int, secret_hash: bytes) -> list:
    script = []

    script.append(Opcodes.OP_IF)  # Normal redeem path

    # Require initiator's secret to be a known length that the redeeming
    # party can audit.This is used to prevent fraud attacks between two
    # currencies that have different maximum data sizes.
    script.append(Opcodes.OP_SIZE)
    script.append(1)  # OP_DATA_1 - 1 + len([secretSize]) (0x01 - 0x01 + 1)
    script.append(secretSize)
    script.append(Opcodes.OP_EQUALVERIFY)

    # Require initiator's secret to be known to redeem the output.
    script.append(Opcodes.OP_SHA256)
    script.append(secretSize)  # OP_DATA_1 - 1 + len(bytes.fromhex(secretHash)) (0x01 - 0x01 + 0x20)
    script.append(secret_hash)
    script.append(Opcodes.OP_EQUALVERIFY)

    # Verify their signature is being used to redeem the output.  This
    # would normally end with OP_EQUALVERIFY OP_CHECKSIG but this has been
    # moved outside of the branch to save a couple bytes.
    script.append(Opcodes.OP_DUP)
    script.append(Opcodes.OP_HASH160)
    script.append(len(to_addr_bytes))  # OP_DATA_1 - 1 + len(bytes.fromhex(to_addr_hash)) (0x01 - 0x01 + 0x14)
    script.append(to_addr_bytes)

    script.append(Opcodes.OP_ELSE)  # Refund path

    # Verify locktime and drop it off the stack (which is not done by CLTV).
    script.append(len(locktime.to_bytes(4, "little")))  # OP_DATA_1 - 1 + 4 (0x01 - 0x01 + 0x04)
    script.append(locktime.to_bytes(4, "little"))
    script.append(Opcodes.OP_CHECKLOCKTIMEVERIFY)
    script.append(Opcodes.OP_DROP)

    # Verify our signature is being used to redeem the output.  This would
    # normally end with OP_EQUALVERIFY OP_CHECKSIG but this has been moved
    # outside of the branch to save a couple bytes.
    script.append(Opcodes.OP_DUP)
    script.append(Opcodes.OP_HASH160)
    script.append(len(my_addr_bytes))  # OP_DATA_1 - 1 + len(bytes.fromhex(my_addr_hash)) (0x01 - 0x01 + 0x14)
    script.append(my_addr_bytes)

    script.append(Opcodes.OP_ENDIF)

    script.append(Opcodes.OP_EQUALVERIFY)
    script.append(Opcodes.OP_CHECKSIG)

    return script


def calc_fee_per_kb(absolute_fee: int, serialize_size: int) -> float:
    return absolute_fee / serialize_size / 1e5


def create_sig(tx: MsgTx, idx: int, pkscript: bytes, addr: str, coind: Coind) -> Tuple[bytes, bytes]:
    privkey = coind.dumpprivkey(addr)
    _, key_bytes = b58_privkey_to_hash160(privkey)
    key = int(key_bytes.hex(), 16)
    sig = raw_tx_in_signature(tx, idx, pkscript, SigHashAll, key)
    return sig, pubkey_from_privkey(key_bytes)


def raw_tx_in_signature(tx: MsgTx, idx: int, sub_script: bytes, hash_type: int, key: int) -> bytes:
    sig_hash = calc_signature_hash(sub_script, hash_type, tx, idx)
    signature = sign_rfc6979(key, sig_hash)
    return signature.signature_serialize() + hash_type.to_bytes(1, "big")


def calc_signature_hash(script: bytes, hash_type: int, tx: MsgTx, idx: int) -> bytes:
    script = parse_script(script)
    if hash_type & sigHashMask == SigHashSingle and idx >= len(tx.tx_outs):
        script_sig = b"\x01"
        return script_sig
    script = remove_opcode(script, Opcodes.OP_CODESEPARATOR)
    tx_copy = tx
    tx_ins = []
    for i, tx_in in enumerate(tx_copy.tx_ins):
        if i == idx:
            sig_script = unparse_script(script)
            tx_in.change_params(sig_script=sig_script)
        else:
            tx_in.change_params(sig_script=b"")
        tx_ins.append(tx_in)
    tx_copy.change_params(tx_in=tx_ins)
    if hash_type & sigHashMask == SigHashNone:
        tx_ins = []
        for i, tx_in in enumerate(tx_copy.tx_ins):
            if i != idx:
                tx_in.change_params(sequence=0)
            tx_ins.append(tx_in)
        tx_copy.change_params(tx_in=tx_ins, tx_out=[])
    elif hash_type & sigHashMask == SigHashSingle:
        tx_ins = []
        tx_outs = tx_copy.tx_outs[:idx + 1]
        tx_out = TxOut(-1, b"")
        for i in range(idx):
            tx_outs[i] = tx_out
        for i, tx_in in enumerate(tx_copy.tx_ins):
            if i != idx:
                tx_in.change_params(sequence=0)
            tx_ins.append(tx_in)
        tx_copy.change_params(tx_in=tx_ins, tx_out=tx_outs)
    if hash_type & SigHashAnyOneCanPay != 0:
        tx_ins = tx_copy.tx_ins[idx:idx + 1]
        tx_copy.change_params(tx_in=tx_ins)
    wbuf = tx_copy.serialize()
    wbuf += hash_type.to_bytes(4, "little")
    return sha256d(wbuf)


def refund_p2sh_contract(contract: bytes, sig: bytes, pubkey: bytes) -> list:
    b = []
    b.append(len(sig))
    b.append(sig)
    b.append(len(pubkey))
    b.append(pubkey)
    b.append(Opcodes.OP_0)
    b.append(Opcodes.OP_PUSHDATA1)
    b.append(len(contract).to_bytes(1, "little"))
    b.append(contract)
    return b


def redeem_p2sh_contract(contract: bytes, sig: bytes, pubkey: bytes, secret: bytes) -> list:
    b = []
    b.append(len(sig))
    b.append(sig)
    b.append(len(pubkey))
    b.append(pubkey)
    b.append(len(secret))
    b.append(secret)
    b.append(Opcodes.OP_1)
    b.append(Opcodes.OP_PUSHDATA1)
    b.append(len(contract).to_bytes(1, "little"))
    b.append(contract)
    return b


def estimate_refund_serialize_size(contract: Union[bytes, list], tx_out: list) -> int:
    if isinstance(contract, list):
        contract = unparse_script(contract)
    contract_push = b""
    contract_push = int_to_bytes(len(contract), contract_push)
    contract_push += contract
    contract_size = len(contract_push)
    return (12 + ver_int_serialize_size(1) +
            ver_int_serialize_size(len(tx_out)) +
            input_size(refundAtomicSwapSigScriptSize + contract_size) +
            sum_output_serialize_sizes(tx_out))


def estimate_redeem_serialize_size(contract: Union[bytes, list], tx_out: list) -> int:
    if isinstance(contract, list):
        contract = unparse_script(contract)
    contract_push = b""
    contract_push = int_to_bytes(len(contract), contract_push)
    contract_push += contract
    contract_size = len(contract_push)
    return (12 + ver_int_serialize_size(1) + ver_int_serialize_size(len(tx_out)) +
            input_size(redeemAtomicSwapSigScriptSize + contract_size) + sum_output_serialize_sizes(tx_out))
