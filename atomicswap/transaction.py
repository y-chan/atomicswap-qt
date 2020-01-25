# Copyright (c) 2014-2020 The btcsuite developers
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
from typing import Tuple, Union

import binascii

from .address import sha256d
from .coind import Coind
from .script import unparse_script, parse_script
from .opcodes import Opcodes
from .util import to_amount


class DeserializeError(Exception):
    pass


class OutPoint:
    def __init__(self, op_hash: bytes, index: int):
        self.hash = op_hash
        self.index = index
        self.serialized_bytes = b""
        self.change_flag = True

    def serialize(self) -> bytes:
        if self.change_flag:
            self.serialized_bytes = self.hash + self.index.to_bytes(4, "little")
            self.change_flag = False
        return self.serialized_bytes

    def serialize_size(self) -> int:
        return len(self.serialize())

    def change_params(self, op_hash=b"", index=0) -> None:
        if op_hash:
            self.hash = op_hash
        if index:
            self.index = index
        if op_hash or index:
            self.change_flag = True

    # debug function
    def show(self) -> dict:
        return {"hash": self.hash[::-1].hex(), "index": self.index}


class TxIn:
    def __init__(self, prev_op: OutPoint, sig_script: bytes, witness: list, sequence: int):
        self.prev_op = prev_op
        self.sig_script = sig_script
        self.witness = witness
        self.sequence = sequence
        self.serialized_bytes = b""
        self.serialized_witness_bytes = b""
        self.change_flag = True
        self.change_witness_flag = True

    def serialize(self, with_sig=True) -> bytes:
        if self.change_flag:
            self.serialized_bytes = self.prev_op.serialize()
            self.serialized_bytes = int_to_bytes(len(self.sig_script), self.serialized_bytes)
            self.serialized_bytes += self.sig_script
            self.serialized_bytes += self.sequence.to_bytes(4, "little")
            self.change_flag = False
        if not with_sig:
            serialized_bytes = self.prev_op.serialize()
            serialized_bytes += self.sequence.to_bytes(4, "little")
            return serialized_bytes
        return self.serialized_bytes

    def serialize_witness(self) -> bytes:
        if self.change_witness_flag:
            self.serialized_witness_bytes = int_to_bytes(len(self.witness), self.serialized_witness_bytes)
            for wit in self.witness:
                self.serialized_witness_bytes = int_to_bytes(len(wit), self.serialized_witness_bytes)
                self.serialized_witness_bytes += wit
            self.change_witness_flag = False
        return self.serialized_witness_bytes

    def serialize_size(self) -> int:
        return len(self.serialize())

    def serialize_witness_size(self) -> int:
        return len(self.serialize_witness())

    def change_params(self, prev_op=None, sig_script=None, witness=None, sequence=None) -> None:
        if isinstance(prev_op, OutPoint):
            self.prev_op = prev_op
        if isinstance(sig_script, bytes):
            self.sig_script = sig_script
        if isinstance(witness, list):
            count = 0
            for wit in witness:
                if isinstance(wit, bytes):
                    count += 1
            if len(witness) == count:
                self.witness = witness
        if isinstance(sequence, int):
            self.sequence = sequence
        if isinstance(prev_op, OutPoint) or isinstance(sig_script, bytes) or \
                isinstance(witness, list) or isinstance(sequence, int):
            self.change_flag = True
            self.change_witness_flag = True

    # debug function
    def show(self) -> dict:
        witness = []
        for wit in self.witness:
            witness.append(wit.hex())
        return {"out_point": self.prev_op.show(),
                "sig_script": self.sig_script.hex(),
                "witness": witness,
                "sequence": self.sequence}


class TxOut:
    def __init__(self, value: int, pkscript: bytes):
        self.value = value
        self.pkscript = pkscript
        self.serialized_bytes = b""
        self.change_flag = True

    def serialize(self) -> bytes:
        if self.change_flag:
            self.serialized_bytes += self.value.to_bytes(8, "little")
            self.serialized_bytes = int_to_bytes(len(self.pkscript), self.serialized_bytes)
            self.serialized_bytes += self.pkscript
            self.change_flag = False
        return self.serialized_bytes

    def serialize_size(self) -> int:
        return len(self.serialize())

    def change_params(self, value=None, pkscript=None) -> None:
        if isinstance(value, int):
            self.value = value
        if isinstance(pkscript, bytes):
            self.pkscript = pkscript
        if isinstance(value, int) or isinstance(pkscript, bytes):
            self.change_flag = True

    # debug function
    def show(self, decimals=8) -> dict:
        return {"value": to_amount(self.value, decimals), "pkscript": self.pkscript.hex()}


class MsgTx:
    def __init__(self, coind: Coind, tx_in: Union[TxIn, list],
                 tx_out: Union[TxOut, list], locktime: int, expiry_height=0):
        self.version = coind.tx_version
        self.tx_ins = [tx_in] if isinstance(tx_in, TxIn) else tx_in
        self.tx_outs = [tx_out] if isinstance(tx_out, TxOut) else tx_out
        self.locktime = locktime
        self.expiry_height = expiry_height
        self.coind = coind
        self.serialized_bytes = b""
        self.serialized_witness_bytes = b""
        self.change_flag = True
        self.change_witness_flag = True

    def serialize(self, witness=False, with_sig=True) -> bytes:
        if self.change_flag or self.change_witness_flag:
            serialized_bytes = self.version.to_bytes(4, "little")
            if self.coind.ver_id:
                header = self.version + 0x80000000
                serialized_bytes = header.to_bytes(4, "little")
                serialized_bytes += self.coind.ver_id.to_bytes(4, "little")
            do_witness = witness and self.has_witness()
            if do_witness:
                serialized_bytes += b"\x00\x01"  # Witness Marker
            serialized_bytes = int_to_bytes(len(self.tx_ins), serialized_bytes)
            for tx_in in self.tx_ins:
                serialized_bytes += tx_in.serialize(with_sig=with_sig)
            serialized_bytes = int_to_bytes(len(self.tx_outs), serialized_bytes)
            for tx_out in self.tx_outs:
                serialized_bytes += tx_out.serialize()
            if do_witness:
                for tx_in in self.tx_ins:
                    serialized_bytes += tx_in.serialize_witness()
            serialized_bytes += self.locktime.to_bytes(4, "little")
            if self.coind.ver_id:
                serialized_bytes += self.expiry_height.to_bytes(4, "little")
                sapling_raw = b"\x00" * (8 + 1 + 1 + 1)  # ValueBalance + spend + output + joinsplits
                serialized_bytes += sapling_raw
            if witness:
                self.change_witness_flag = False
                self.serialized_witness_bytes = serialized_bytes
            else:
                self.change_flag = False
                self.serialized_bytes = serialized_bytes
        if witness:
            return self.serialized_witness_bytes
        return self.serialized_bytes

    def serialize_witness(self) -> bytes:
        return self.serialize(True)

    def serialize_size(self):
        if self.coind.ver_id:
            return len(self.serialize(with_sig=False))
        return len(self.serialize())

    def serialize_witness_size(self):
        return len(self.serialize_witness())

    def has_witness(self) -> bool:
        has_witness = False
        for tx_in in self.tx_ins:
            if tx_in.witness:
                has_witness = True
                break
        return has_witness

    def add_tx_in(self, tx_in: TxIn) -> None:
        self.tx_ins.append(tx_in)
        self.change_flag = True
        self.change_witness_flag = True

    def add_tx_out(self, tx_out: TxOut) -> None:
        self.tx_outs.append(tx_out)
        self.change_flag = True
        self.change_witness_flag = True

    def change_params(self, tx_in=None, tx_out=None, locktime=None):
        if isinstance(tx_in, list):
            invalid = False
            for tx in tx_in:
                if not isinstance(tx, TxIn):
                    invalid = True
            if not invalid:
                self.tx_ins = tx_in
        if isinstance(tx_in, TxIn):
            self.tx_ins = [tx_in]
        if isinstance(tx_out, list):
            invalid = False
            for tx in tx_out:
                if not isinstance(tx, TxOut):
                    invalid = True
            if not invalid:
                self.tx_outs = tx_out
        if isinstance(tx_out, TxOut):
            self.tx_outs = [tx_out]
        if isinstance(locktime, int):
            self.locktime = locktime
        if isinstance(tx_in, list) or isinstance(tx_in, TxIn) or isinstance(tx_out, list) \
                or isinstance(tx_out, TxOut) or isinstance(locktime, int):
            self.change_flag = True
            self.change_witness_flag = True

    def get_txid(self) -> bytes:
        if self.coind.ver_id:
            return sha256d(self.serialize(with_sig=False))[::-1]
        return sha256d(self.serialize())[::-1]

    def get_txhash(self) -> bytes:
        return sha256d(self.serialize_witness())[::-1]

    # debug function
    def show(self) -> dict:
        tx_ins = []
        tx_outs = []
        for tx_in in self.tx_ins:
            tx_ins.append(tx_in.show())
        for tx_out in self.tx_outs:
            tx_outs.append(tx_out.show(self.coind.decimals))
        result = {"txid": self.get_txid().hex(),
                  "txhash": self.get_txhash().hex(),
                  "version": self.version,
                  "locktime": self.locktime,
                  "vin": tx_ins,
                  "vout": tx_outs}
        if self.expiry_height:
            result["expiry_height"] = self.expiry_height
        return result


def deserialize(tx_hex: str, coind: Coind, witness=False) -> MsgTx:
    tx_bytes = binascii.a2b_hex(tx_hex)
    version, tx_bytes = read_int(tx_bytes, 4)
    if coind.ver_id:
        version = version & 0x7fffffff
        ver_id, tx_bytes = read_int(tx_bytes, 4)
        assert ver_id == coind.ver_id
    count, tx_bytes = read_ver_int(tx_bytes)
    flag = 0
    if count == 0 and witness:
        flag, tx_bytes = read_int(tx_bytes, 1)
        if flag != 1:
            raise DeserializeError("This rawtransaction hasn't SegWit!")
        count, tx_bytes = read_ver_int(tx_bytes)
    tx_ins = []
    for i in range(count):
        op_hash, tx_bytes = read_bytes(tx_bytes, 32)
        index, tx_bytes = read_int(tx_bytes, 4)
        out_point = OutPoint(op_hash, index)
        size, tx_bytes = read_ver_int(tx_bytes)
        signature_script, tx_bytes = read_bytes(tx_bytes, size)
        sequence, tx_bytes = read_int(tx_bytes, 4)
        tx_in = TxIn(out_point, signature_script, [], sequence)
        tx_ins.append(tx_in)
    count, tx_bytes = read_ver_int(tx_bytes)
    tx_outs = []
    for i in range(count):
        value, tx_bytes = read_int(tx_bytes, 8)
        size, tx_bytes = read_ver_int(tx_bytes)
        pkscript, tx_bytes = read_bytes(tx_bytes, size)
        if pkscript == b"" and witness:
            raise DeserializeError("This transaction hasn't SegWit!")
        tx_out = TxOut(value, pkscript)
        tx_outs.append(tx_out)
    if flag != 0 and witness:
        for tx_in in tx_ins:
            wit_count, tx_bytes = read_ver_int(tx_bytes)
            tx_witness = []
            for i in range(wit_count):
                size, tx_bytes = read_ver_int(tx_bytes)
                tx, tx_bytes = read_bytes(tx_bytes, size)
                tx_witness.append(tx)
            tx_in.change_params(witness=tx_witness)
    locktime, tx_bytes = read_int(tx_bytes, 4)
    if coind.ver_id:
        expiry_height, tx_bytes = read_int(tx_bytes, 4)
        assert tx_bytes == b"\x00" * (8 + 1 + 1 + 1)  # Sapling Raw: ValueBalance + spend + output + joinsplits
        tx_bytes = b""
    else:
        expiry_height = 0
    assert tx_bytes == b""
    assert coind.tx_version == version
    return MsgTx(coind, tx_ins, tx_outs, locktime, expiry_height)


def deserialize_witness(tx_hex: str, coind: Coind) -> MsgTx:
    return deserialize(tx_hex, coind, True)


def read_ver_int(byte: bytes) -> Tuple:
    discriminant = int.from_bytes(byte[:1], "little")
    if discriminant == 0xff:
        size = 8
    elif discriminant == 0xfe:
        size = 4
    elif discriminant == 0xfd:
        size = 2
    else:
        return discriminant, byte[1:]
    out = int.from_bytes(byte[1:1 + size], "little")
    return out, byte[1 + size:]


def read_int(byte: bytes, len: int) -> Tuple[int, bytes]:
    out = int.from_bytes(byte[:len], "little")
    return out, byte[len:]


def read_bytes(byte: bytes, len: int) -> Tuple[bytes, bytes]:
    out = byte[:len]
    return out, byte[len:]


def int_to_bytes(count: int, serialized_bytes: bytes) -> bytes:
    if count < 0xfd:
        return serialized_bytes + count.to_bytes(1, "little")
    if count <= 0xffff:
        hed = 0xfd
        return serialized_bytes + hed.to_bytes(1, "little") + count.to_bytes(2, "little")
    if count <= 0xffffffff:
        hed = 0xfe
        return serialized_bytes + hed.to_bytes(1, "little") + count.to_bytes(4, "little")
    hed = 0xff
    return serialized_bytes + hed.to_bytes(1, "little") + count.to_bytes(8, "little")


def ver_int_serialize_size(param: Union[int, bytes]) -> int:
    if isinstance(param, bytes):
        discriminant = int.from_bytes(param[:1], "little")
    else:
        discriminant = param
    if discriminant == 0xff:
        size = 1 + 8
    elif discriminant == 0xfe:
        size = 1 + 4
    elif discriminant == 0xfd:
        size = 1 + 2
    else:
        size = 1
    return size


def atomic_swap_extract(contract: Union[bytes, list]) -> dict:
    if isinstance(contract, list):
        contract = unparse_script(contract)
    pushes = parse_script(contract)
    standard_contract = [Opcodes.OP_IF, Opcodes.OP_SIZE, 1, Opcodes.OP_EQUALVERIFY, Opcodes.OP_SHA256,
                         32, Opcodes.OP_EQUALVERIFY, Opcodes.OP_DUP, Opcodes.OP_HASH160, 20, Opcodes.OP_ELSE,
                         4, Opcodes.OP_CHECKLOCKTIMEVERIFY, Opcodes.OP_DROP, Opcodes.OP_DUP, Opcodes.OP_HASH160,
                         20, Opcodes.OP_ENDIF, Opcodes.OP_EQUALVERIFY, Opcodes.OP_CHECKSIG]
    assert standard_contract == pushes["script"], "This isn't atomicswap contract!"
    assert int.from_bytes(pushes["data"][0], "little") == 32, "This isn't atomicswap contract!"
    secret_hash = pushes["data"][1]
    receiver_addr_hash = pushes["data"][2]
    locktime = int.from_bytes(pushes["data"][3], "little")
    sender_addr_hash = pushes["data"][4]
    return {"secret_hash": secret_hash,
            "recipient_addr_hash": receiver_addr_hash,
            "refund_addr_hash": sender_addr_hash,
            "locktime": locktime}


def input_size(sig_script_size: int) -> int:
    return 32 + 4 + ver_int_serialize_size(sig_script_size) + sig_script_size + 4


def sum_output_serialize_sizes(tx_out: list) -> int:
    serialize_size = 0
    for tx in tx_out:
        serialize_size += tx_out_serialize_size(tx)
    return serialize_size


def tx_out_serialize_size(tx_out: TxOut) -> int:
    return 8 + ver_int_serialize_size(len(tx_out.pkscript)) + len(tx_out.pkscript)


def fee_for_serialize_size(fee_per_kb: int, tx_size: int) -> int:
    fee = fee_per_kb * tx_size // 1000
    if fee == 0 and fee_per_kb > 0:
        fee = fee_per_kb
    return fee


def get_dust_threshold(script_size: int, fee_per_kb: int) -> int:
    total_size = 8 + ver_int_serialize_size(script_size) + script_size + 148
    byte_fee = fee_per_kb // 1000
    relay_fee = total_size * byte_fee
    return 3 * relay_fee


def is_dust_amount(amount: int, script_size: int, fee_per_kb: int) -> bool:
    return amount < get_dust_threshold(script_size, fee_per_kb)


def is_dust_output(output: TxOut, fee_per_kb: int) -> bool:
    if is_unspendable(output.pkscript):
        return True
    return is_dust_amount(output.value, len(output.pkscript), fee_per_kb)


def is_unspendable(pkscript: bytes) -> bool:
    pops = parse_script(pkscript)
    return len(pops) > 0 and pops["script"][0] == Opcodes.OP_RETURN
