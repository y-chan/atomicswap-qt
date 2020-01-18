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

from atomicswap.auditcontract import auditcontract
from atomicswap.coind import make_coin_data, Coind
from atomicswap.extractsecret import extractsecret
from atomicswap.initiate import initiate
from atomicswap.participate import participate
from atomicswap.redeem import redeem
from atomicswap.refund import refund


def command(cmd: str, params: list) -> None:
    cmd_list = ["initiate", "participate", "auditcontract", "extractsecret", "redeem", "refund", "help"]
    cmd_bool = cmd in cmd_list

    def params_invalid() -> None:
        print("params invalid")

    def initiate_help() -> None:
        print("command: python3 run_atomicswap command initiate <participator's address> <amount> <coin name>")

    def participate_help() -> None:
        print("command: python3 run_atomicswap command participate "
              "<initiator's address> <amount> <secret hash> <coin name>")

    def auditcontract_help() -> None:
        print("command: python3 run_atomicswap command auditcontract <contract> <contract tx> <coin name>")

    def extractsecret_help() -> None:
        print("command: python3 run_atomicswap command extractsecret <redeem tx> <secret hash> <coin name>")

    def redeem_help() -> None:
        print("command: python3 run_atomicswap command redeem <contract> <contract tx> <secret> <coin name>")

    def refund_help() -> None:
        print("command: python3 run_atomicswap command refund <contract> <contract tx> <coin name>")

    def help() -> None:
        print("command list:")
        initiate_help()
        participate_help()
        auditcontract_help()
        redeem_help()
        extractsecret_help()
        refund_help()

    def publish_transaction(tx_hex: str, tx_name: str, coind: Coind) -> None:
        while True:
            print("Publish {} transaction? [y/N]:".format(tx_name), end="")
            i = input()
            i = i.lower()
            if i == "y" or i == "yes":
                result = coind.sendrawtransaction(tx_hex)
                print("Published {} transaction ({})".format(tx_name, result))
                return
            elif i == "n" or i == "no":
                return
            else:
                print("Please answer y or n")

    if cmd_bool:
        params_len = len(params)
        if cmd == "initiate":
            if params_len == 3:
                _, coind = make_coin_data(params[2])
                params[1] = int(params[1]) * 10 ** 8
                params[2] = coind
                _, b = initiate(*params)
                publish_transaction(b.contractTx.serialize_witness().hex(), "initiate", coind)
            else:
                params_invalid()
                initiate_help()
        elif cmd == "participate":
            if params_len == 4:
                _, coind = make_coin_data(params[3])
                params[2] = int(params[2]) * 10 ** 8
                params[3] = coind
                b = participate(*params)
                publish_transaction(b.contractTx.serialize_witness().hex(), "participate", coind)
            else:
                params_invalid()
                participate_help()
        elif cmd == "auditcontract":
            if params_len == 3:
                _, coind = make_coin_data(params[2])
                params[2] = coind
                auditcontract(*params)
            else:
                params_invalid()
                auditcontract_help()
        elif cmd == "extractsecret":
            if params_len == 3:
                _, coind = make_coin_data(params[2])
                params[2] = coind
                extractsecret(*params)
            else:
                params_invalid()
                extractsecret_help()
        elif cmd == "redeem":
            if params_len == 4:
                _, coind = make_coin_data(params[3])
                params[3] = coind
                redeem_tx = redeem(*params)
                publish_transaction(redeem_tx.serialize_witness().hex(), "redeem", coind)
            else:
                params_invalid()
                redeem_help()
        elif cmd == "refund":
            if params_len == 3:
                _, coind = make_coin_data(params[2])
                params[2] = coind
                refund_tx = refund(*params)
                publish_transaction(refund_tx.serialize_witness().hex(), "refund", coind)
            else:
                params_invalid()
                refund_help()
        elif cmd == "help":
            help()
    else:
        print("Invalid command: {}".format(cmd))
        help()
    return
