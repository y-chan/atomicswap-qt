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

import base64
import json
import platform
from urllib import request
from typing import Tuple, Union

coins = "./atomicswap/coins/"


class GetFeeError(Exception): pass


class InvalidRPCError(Exception): pass


class GetConfigError(Exception): pass


class RestartWallet(Exception): pass


class Coind:
    def __init__(self, name: str, unit: str, p2pkh: Union[int, list], p2sh: Union[int, list],
                 bech32_hrp: str, port: int, user: str, pwd: str, sign_wallet: bool, tx_version=2):
        self.name = name
        self.unit = unit
        self.p2pkh = p2pkh
        self.p2sh = p2sh
        self.bech32_hrp = bech32_hrp
        self.url = 'http://localhost:%s' % port
        self.auth = base64.b64encode((user + ":" + pwd).encode('utf-8'))
        self.headers = {'content-type': 'text/plain;', "Authorization": "Basic " + self.auth.decode('utf-8')}
        self.sign_wallet = sign_wallet
        self.tx_version = tx_version

    def getrawchangeaddress(self) -> str:
        data = '{"jsonrpc":"1.0","id":"curltext","method":"getrawchangeaddress","params":["legacy"]}'
        req = request.Request(self.url, data.encode(), self.headers)
        with request.urlopen(req) as res:
            result = json.loads(res.read())
        addr = result["result"]
        if addr is None:
            data = '{"jsonrpc":"1.0","id":"curltext","method":"getrawchangeaddress","params":[]}'
            req = request.Request(self.url, data.encode(), self.headers)
            with request.urlopen(req) as res:
                result = json.loads(res.read())
            addr = result["result"]
            if addr is None:
                raise InvalidRPCError(result["error"]["message"])
        return addr

    def dumpprivkey(self, addr: str) -> str:
        data = '{"jsonrpc":"1.0","id":"curltext","method":"dumpprivkey","params":["%s"]}' % addr
        req = request.Request(self.url, data.encode(), self.headers)
        with request.urlopen(req) as res:
            result = json.loads(res.read())
        wif = result["result"]
        if wif is None:
            raise InvalidRPCError(result["error"]["message"])
        return wif

    def fundrawtransaction(self, params: dict) -> dict:
        json_dict = {"feeRate": params["fee"]}
        dict_str = json.dumps(json_dict)
        tx_hex = params["hex"]
        json_params = f'["{tx_hex}", {dict_str}]'
        data = '{"jsonrpc": "1.0", "id": "curltext", "method": "fundrawtransaction", "params": %s}' % json_params
        req = request.Request(self.url, data.encode(), self.headers)
        with request.urlopen(req) as res:
            result = json.loads(res.read())
        tx_dict = result["result"]
        if tx_dict is None and 'fundrawtransaction "hexstring"' in str(result["error"]):
            data = '{"jsonrpc": "1.0", "id": "curltext", "method": "fundrawtransaction", "params": ["%s"]}' % tx_hex
            req = request.Request(self.url, data.encode(), self.headers)
            with request.urlopen(req) as res:
                result = json.loads(res.read())
            tx_dict = result["result"]
        if tx_dict is None:
            raise InvalidRPCError(result["error"]["message"])
        return tx_dict

    def signrawtransaction(self, tx_hex: str) -> dict:
        if self.sign_wallet:
            data = '{"jsonrpc":"1.0","id":"curltext","method":"signrawtransactionwithwallet","params":["%s"]}' % tx_hex
        else:
            data = '{"jsonrpc":"1.0","id":"curltext","method":"signrawtransaction","params":["%s"]}' % tx_hex
        req = request.Request(self.url, data.encode(), self.headers)
        with request.urlopen(req) as res:
            result = json.loads(res.read())
        tx_dict = result["result"]
        if tx_dict is None:
            raise InvalidRPCError(result["error"]["message"])
        return tx_dict

    def sendrawtransaction(self, tx_hex: str) -> str:
        data = '{"jsonrpc":"1.0","id":"curltext","method":"sendrawtransaction","params":[%s]}' % tx_hex
        req = request.Request(self.url, data.encode(), self.headers)
        with request.urlopen(req) as res:
            result = json.loads(res.read())
        tx_dict = result["result"]
        if tx_dict is None:
            raise InvalidRPCError(result["error"]["message"])
        return tx_dict

    def info(self, method: str) -> dict:
        data = '{"jsonrpc":"1.0","id":"curltext","method":"%s","params":[]}' % method
        req = request.Request(self.url, data.encode(), self.headers)
        with request.urlopen(req) as res:
            result = json.loads(res.read())
        info = result["result"]
        if info is None:
            raise InvalidRPCError(result["error"]["message"])
        return info

    def getinfo(self) -> dict:
        return self.info("getinfo")

    def getwalletinfo(self) -> dict:
        return self.info("getwalletinfo")

    def getblockchaininfo(self) -> dict:
        return self.info("getblockchaininfo")

    def getnetworkinfo(self) -> dict:
        return self.info("getnetworkinfo")

    def estimatesmartfee(self, blocks=6) -> dict:
        data = '{"jsonrpc":"1.0","id":"curltext","method":"estimatesmartfee","params":[%s]}' % blocks
        req = request.Request(self.url, data.encode(), self.headers)
        with request.urlopen(req) as res:
            result = json.loads(res.read())
        fee = result["result"]
        if fee is None:
            raise InvalidRPCError(result["error"]["message"])
        return fee

    def get_fee_per_byte(self) -> Tuple[int, int]:
        try:
            relayfee = int(self.getnetworkinfo()["relayfee"] * 1e8)
            paytxfee = int(self.getwalletinfo()["paytxfee"] * 1e8)
        except InvalidRPCError:
            raise GetFeeError("Can't get fee amount!")

        if paytxfee != 0:
            maxfee = paytxfee
            if relayfee > maxfee:
                maxfee = relayfee
            return maxfee, relayfee

        try:
            usefee = int(self.estimatesmartfee()["feerate"] * 1e8)
            if relayfee > usefee:
                usefee = relayfee
            return usefee, relayfee
        except:
            pass

        print("warning: falling back to mempool relay fee policy")
        return relayfee, relayfee


def make_coin_data(path: str, coin: str) -> Tuple[int, Coind]:
    os_name = platform.system()
    low = coin.lower()
    conf_path = '/' + low + '.conf'
    if "Testnet" in coin:
        low, testnet = low.split()
        conf_path = '/' + testnet + '/' + low + '.conf'
        with open(coins + low + '_' + testnet + '.json') as f:
            coin_json = json.loads(f.read())
    else:
        with open(coins + low + '.json') as f:
            coin_json = json.loads(f.read())
    if os_name == 'Linux':
        conf_full_path = path + low + conf_path
    else:
        conf_full_path = path + coin + conf_path

    def make_conf():
        with open(conf_full_path, mode='w') as f:
            conf_list = ['server=1', 'rpcallowip=127.0.0.1',
                         f'rpcport={coin_json["port"]}',
                         'rpcuser=user', 'rpcpassword=pass']
            f.write('\n'.join(conf_list))
        raise RestartWallet("Please restart coind or coin-qt")

    try:
        with open(conf_full_path) as f:
            conf_list = [s.strip().replace(' ', '') for s in f.readlines()]
            server_flag = False
            rpc_flag = 0
            user = ''
            pwd = ''
            port = 0
            for conf in conf_list:
                if 'server=1' == conf:
                    server_flag = True
                if 'rpcallowip=' in conf:
                    rpc_flag += 1
                if 'rpcuser=' in conf:
                    rpc_flag += 1
                    user = conf[8:]
                if 'rpcpassword=' in conf:
                    pwd = conf[12:]
                    rpc_flag += 1
                if 'rpcport=' in conf:
                    port = conf[8:]
                    rpc_flag += 1
            if not server_flag:
                raise GetConfigError('"server=1" is not found!')
            if rpc_flag != 4:
                raise GetConfigError('rpc setting is but!')
    except FileNotFoundError:
        make_conf()
    except GetConfigError:
        make_conf()
    try:
        coind = Coind(coin_json["name"], coin_json["unit"], coin_json["p2pkh"],
                      coin_json["p2sh"], coin_json["bech32_hrp"], port, user, pwd, False, coin_json["tx_ver"])
    except KeyError:
        coind = Coind(coin_json["name"], coin_json["unit"], coin_json["p2pkh"],
                      coin_json["p2sh"], coin_json["bech32_hrp"], port, user, pwd, False)
    return coin_json["req_ver"], coind
