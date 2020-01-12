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
from typing import Union, Tuple

from .address import b58_address_to_hash160, hash160_to_b58_address
from .coind import Coind
from .opcodes import opcodes, opcode_search
from .segwit_addr import encode


class ParseOrUnParseError(Exception):
    pass


class ScriptType(IntEnum):
    Pubkey = 0x01
    PubkeyHash = 0x02
    ScriptHash = 0x03
    MultiSig = 0x04
    WitnessPubkeyHash = 0x05
    WitnessScriptHash = 0x06
    NullData = 0x07
    Unknown = 0xff


def pay_to_addr_script(addr: str, coind: Coind) -> list:
    addr_type, hash160 = b58_address_to_hash160(addr, coind)
    if isinstance(coind.p2pkh, list) and isinstance(coind.p2sh, list):
        if addr_type == bytes(coind.p2pkh):
            out = pay_to_pubkey_hash_script(hash160)
        elif addr_type == bytes(coind.p2sh):
            out = pay_to_script_hash_script(hash160)
        else:
            raise Exception("Not support Address Type!")
    else:
        if addr_type == bytes([coind.p2pkh]):
            out = pay_to_pubkey_hash_script(hash160)
        elif addr_type == bytes([coind.p2sh]):
            out = pay_to_script_hash_script(hash160)
        else:
            raise Exception("Not support Address Type!")
    return out


def pay_to_pubkey_hash_script(addr_hash: bytes) -> list:
    script = []

    script.append(opcodes.OP_DUP)
    script.append(opcodes.OP_HASH160)
    script.append(len(addr_hash))
    script.append(addr_hash)
    script.append(opcodes.OP_EQUALVERIFY)
    script.append(opcodes.OP_CHECKSIG)

    return script


def pay_to_script_hash_script(addr_hash: bytes) -> list:
    script = []

    script.append(opcodes.OP_HASH160)
    script.append(len(addr_hash))
    script.append(addr_hash)
    script.append(opcodes.OP_EQUAL)
    return script


def unparse_script(script: Union[dict, list]) -> bytes:
    out = b''
    if isinstance(script, list):
        for i in script:
            if isinstance(i, int):
                out += i.to_bytes(1, 'little')
            elif isinstance(i, bytes):
                out += i
            else:
                raise ParseOrUnParseError("Can't convert contract!")
    else:
        parsed_script = script["script"]
        data = script["data"]
        count = 0
        for i in parsed_script:
            opcode, opcode_bool = opcode_search(i)
            out += i.to_bytes(1, 'little')
            if not opcode_bool:
                out += data[count]
                count += 1
            elif opcode == opcodes.OP_PUSHDATA1:
                for i in range(2):
                    out += data[count]
                    count += 1
            elif opcode == opcodes.OP_PUSHDATA2:
                for i in range(3):
                    out += data[count]
                    count += 1
            elif opcode == opcodes.OP_PUSHDATA4:
                for i in range(5):
                    out += data[count]
                    count += 1
    return out


def mix_script(script: dict) -> list:
    out = []
    parsed_script = script["script"]
    data = script["data"]
    count = 0
    for i in parsed_script:
        opcode, opcode_bool = opcode_search(i)
        out.append(opcode)
        if not opcode_bool:
            out.append(data[count])
            count += 1
        elif opcode == opcodes.OP_PUSHDATA1:
            for i in range(2):
                out += data[count]
                count += 1
        elif opcode == opcodes.OP_PUSHDATA2:
            for i in range(3):
                out += data[count]
                count += 1
        elif opcode == opcodes.OP_PUSHDATA4:
            for i in range(5):
                out += data[count]
                count += 1
    return out


def parse_script(script: Union[bytes, list]) -> dict:
    parsed_script = []
    timer = 0
    data = 0
    timer_bytes = b''
    parsed_data = b''
    parsed_data_list = []
    for i in range(len(script)):
        if timer > 0:
            timer -= 1
            if isinstance(script, bytes):
                if timer > 0:
                    parsed_data += script[i:i + 1]
                else:
                    parsed_data += script[i:i + 1]
                    parsed_data_list.append(parsed_data)
                    parsed_data = b''
            else:
                parsed_data_list.append(script[i:i + 1])
            continue
        elif data > 0:
            data -= 1
            if isinstance(script, bytes):
                if data > 0:
                    timer_bytes += script[i:i + 1]
                else:
                    timer_bytes += script[i:i + 1]
                    timer = int.from_bytes(timer_bytes, 'little')
                    parsed_data_list.append(timer_bytes)
                    timer_bytes = b''
            else:
                timer = int.from_bytes(script[i:i + 1], 'little')
                parsed_data_list.append(script[i:i + 1])
        opcode = int.from_bytes(script[i:i + 1], 'little')
        opcode, script_bool = opcode_search(opcode)
        if not script_bool and isinstance(script, bytes):
            timer = opcode
        elif not script_bool and isinstance(script, list):
            timer = 1
        elif opcode == opcodes.OP_PUSHDATA1:
            data = 1
        elif opcode == opcodes.OP_PUSHDATA2:
            if isinstance(script, bytes):
                data = 2
            else:
                data = 1
        elif opcode == opcodes.OP_PUSHDATA4:
            if isinstance(script, bytes):
                data = 4
            else:
                data = 1
        parsed_script.append(opcode)
    return {"script": parsed_script, "data": parsed_data_list}


def extract_pkccript_addrs(pkscript: Union[bytes, list], coind: Coind) -> Tuple[ScriptType, str]:
    pops = parse_script(pkscript)
    script = pops["script"]
    data = pops["data"]
    script_type = discriminate_script_type(script, data)
    addr = ""
    if script_type == ScriptType.PubkeyHash:
        addr = hash160_to_b58_address(data[0], coind.p2pkh)
    elif script_type == ScriptType.WitnessPubkeyHash:
        addr = encode(coind.bech32_hrp, 0, data[0])
    elif script_type == ScriptType.ScriptHash:
        addr = hash160_to_b58_address(data[0], coind.p2sh)
    elif script_type == ScriptType.WitnessScriptHash:
        addr = encode(coind.bech32_hrp, 0, data[0])
    return script_type, addr


def discriminate_script_type(script: list, data: list) -> ScriptType:
    is_pubkeyhash = [opcodes.OP_DUP, opcodes.OP_HASH160, 20, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG]
    is_witness_pubkeyhash = [opcodes.OP_0, 20]
    is_scripthash = [opcodes.OP_HASH160, 20, opcodes.OP_EQUAL]
    is_witness_scripthash = [opcodes.OP_0, 32]
    script_len = len(script)
    if script_len == 2 and (len(data[0]) == 33 or len(data[0]) == 65) \
            and script[1] == opcodes.OP_CHECKSIG:
        return ScriptType.Pubkey
    elif script == is_pubkeyhash:
        return ScriptType.PubkeyHash
    elif script == is_witness_pubkeyhash:
        return ScriptType.WitnessPubkeyHash
    elif script == is_scripthash:
        return ScriptType.ScriptHash
    elif script == is_witness_scripthash:
        return ScriptType.WitnessScriptHash
    elif is_multisig(script, data):
        return ScriptType.MultiSig
    elif is_nulldata(script, data):
        return ScriptType.NullData
    return ScriptType.Unknown


def is_smallint(opcode: int) -> bool:
    if opcode == opcodes.OP_0 and opcodes.OP_1 <= opcode <= opcodes.OP_16:
        return True
    return False


def as_smallint(opcode: int) -> int:
    if opcode == opcodes.OP_0:
        return 0
    return opcode - (opcodes.OP_1 - 1)


def is_multisig(script: list, data: list) -> bool:
    script_len = len(script)
    if script_len < 4 or not is_smallint(script[0]) \
            or not is_smallint(script[script_len - 2]) \
            or script[script_len - 1] != opcodes.OP_CHECKMULTISIG \
            or script_len - 2 - 1 != as_smallint(script[script_len - 2]):
        return False
    for opcode in data[1:script_len - 2]:
        if len(opcode) != 33 and len(opcode) != 65:
            return False
    return True


def is_nulldata(script: list, data: list) -> bool:
    script_len = len(script)
    if script_len == 1 and script[0] == opcodes.OP_RETURN:
        return True
    return script_len == 2 and script[0] == opcodes.OP_RETURN \
           and (is_smallint(script[1]) or script[1] <= opcodes.OP_PUSHDATA4) \
           and len(data[0]) <= 80
