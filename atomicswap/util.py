# Copyright (c) 2011-2020 The Electrum Developers
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

import platform
import math
import json
import os

status_icons = [
    "icons8-setting.png",  # initiate or participate
    "icons8-check.png",  # complete atomicswap
    "icons8-risk.png"  # locktime expiry
]

coin_list = [
    "Bitcoin",
    "Litecoin",
    "Monacoin",
    "BitZeny",
    # "Koto",
    "VIPSTARCOIN",
    "Bellcoin",
    "Sugarchain",
    "MicroBitcoin"
]

pkg_dir = os.path.split(os.path.realpath(__file__))[0]


def resource_path(*parts):
    return os.path.join(pkg_dir, *parts)


def get_path() -> str:
    os_name = platform.system()
    if os_name == "Windows":
        path = os.path.expanduser("~/AppData/Roaming/")
    elif os_name == "Darwin":
        path = os.path.expanduser("~/Library/Application Support/")
    elif os_name == "Linux":
        path = os.path.expanduser("~/")
    else:
        raise Exception("Your using OS isn't support!")
    return path


class History_DB:
    def __init__(self):
        self.path = os.path.join(get_path(), "atomicswap-qt")
        self.db_name = "history_db"
        self.data = []
        self.load_db()
        self.auto_status_update()

    def load_db(self) -> None:
        try:
            with open(os.path.join(self.path, self.db_name)) as db:
                self.data = json.loads(db.read())
        except FileNotFoundError:
            self.write_db()

    def write_db(self) -> None:
        os.makedirs(self.path, exist_ok=True)
        with open(os.path.join(self.path, self.db_name), "w") as db:
            db.write(json.dumps(self.data))

    def add_data(self, data: dict) -> None:
        self.data.append(data)
        self.write_db()

    def delete_data(self, key: str) -> None:
        index = self.get_data_index(key)
        self.data = self.data[:index] + self.data[index + 1:]
        self.write_db()

    def get_data(self, key: str) -> dict:
        for data in self.data:
            if data["SecretHash"] == key:
                return data
        raise Exception("Data not found")

    def get_data_index(self, key: str) -> int:
        for i, data in enumerate(self.data):
            if data["SecretHash"] == key:
                return i
        raise Exception("Data not found")

    def keys(self) -> list:
        keys = []
        for data in self.data:
            keys.append(data["SecretHash"])
        return keys

    def count(self) -> int:
        return len(self.keys())

    def auto_status_update(self) -> None:
        from .coind import make_coin_data
        from .auditcontract import auditcontract
        for key in self.keys():
            data = self.get_data(key)
            _, coind = make_coin_data(data["Send"]["Coin"])
            try:
                reach_bool, _, _ = auditcontract(data["Send"]["Contract"],
                                                 data["Send"]["Transaction"],
                                                 coind,
                                                 False)
                if not reach_bool and not data["Receive"]["Redeem"]:
                    data["Status"] = 2
                    self.delete_data(key)
                    self.add_data(data)
            except:
                pass
        return

def to_satoshis(value: float, decimals=8) -> int:
    return int(value * math.pow(10, decimals))

def to_amount(value: int, decimals=8) -> float:
    return round(value / math.pow(10, decimals), decimals)

def amount_format(value: float, decimals=8) -> str:
    return "%.*f" % (decimals, value)
