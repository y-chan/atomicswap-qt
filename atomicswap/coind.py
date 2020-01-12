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

import os
import json
import requests
import platform

from typing import Tuple, Union

from .util import get_path, resource_path


class GetFeeError(Exception):
    pass

class InvalidRPCError(Exception):
    pass

class GetConfigError(Exception):
    pass

class RestartWallet(Exception):
    pass

class Coind:
    def __init__(self, name: str, unit: str, p2pkh: Union[int, list], p2sh: Union[int, list], bech32_hrp: str,
                 port: int, user: str, pwd: str, sign_wallet: bool, tx_version=2, ver_id=0):
        self.name = name
        self.unit = unit
        self.p2pkh = p2pkh
        self.p2sh = p2sh
        self.bech32_hrp = bech32_hrp
        self.endpoint = "http://{}:{}@127.0.0.1:{}/".format(user, pwd, port)
        self.url = 'http://localhost:' + str(port)
        self.user = user
        self.pwd = pwd
        self.sign_wallet = sign_wallet
        self.tx_version = tx_version
        self.ver_id = ver_id

    def make_request(self, method: str, params=[]) -> dict:
        headers = {'content-type': 'text/plain;'}
        data = json.dumps({'id': None, 'method': method, 'params': params})

        try:
            return requests.post(self.endpoint, headers=headers, data=data).json()
        except Exception:
            return {
                'error': {
                    'message': '{} backend is down or not responding'.format(self.name)
                }
            }

    def simple_request(self, method: str) -> dict:
        result = self.make_request(method)

        if result['result'] is None:
            raise InvalidRPCError(result['error']['message'])

        return result['result']

    def getinfo(self) -> dict:
        return self.simple_request('getinfo')

    def getwalletinfo(self) -> dict:
        return self.simple_request('getwalletinfo')

    def getblockchaininfo(self) -> dict:
        return self.simple_request('getblockchaininfo')

    def getnetworkinfo(self) -> dict:
        return self.simple_request('getnetworkinfo')

    def getblockcount(self) -> int:
        return int(self.simple_request('getblockcount'))

    def getnewaddress(self) -> str:
        result = self.make_request('getnewaddress', ['', 'legacy'])
        address = result['result']

        if address is None:
            result = self.make_request('getnewaddress')
            address = result['result']

            if address is None:
                raise InvalidRPCError(result['error']['message'])

        return address

    def getrawchangeaddress(self) -> str:
        result = self.make_request('getrawchangeaddress', ['legacy'])
        address = result['result']

        if address is None:
            result = self.make_request('getrawchangeaddress')
            address = result['result']

            if address is None:
                raise InvalidRPCError(result['error']['message'])

        return address

    def dumpprivkey(self, address: str) -> str:
        result = self.make_request('dumpprivkey', [address])
        wif = result['result']

        if wif is None:
            raise InvalidRPCError(result['error']['message'])

        return wif

    def fundrawtransaction(self, tx_hex: str, fee: float) -> dict:
        result = self.make_request('fundrawtransaction', [tx_hex, {'feeRate': fee}])
        tx_dict = result['result']

        if tx_dict is None:
            result = self.make_request('fundrawtransaction', [tx_hex])
            tx_dict = result['result']

            if tx_dict is None:
                raise InvalidRPCError(result["error"]["message"])

        return tx_dict

    def signrawtransaction(self, tx_hex: str) -> dict:
        if self.sign_wallet:
            result = self.make_request('signrawtransactionwithwallet', [tx_hex])

        else:
            result = self.make_request('signrawtransaction', [tx_hex])

        tx_dict = result['result']

        if tx_dict is None:
            raise InvalidRPCError(result['error']['message'])

        return tx_dict

    def sendrawtransaction(self, tx_hex: str) -> str:
        result = self.make_request('sendrawtransaction', [tx_hex])
        tx_dict = result['result']

        if tx_dict is None:
            raise InvalidRPCError(result['error']['message'])

        return tx_dict

    def estimatesmartfee(self, blocks=6) -> dict:
        result = self.make_request('estimatesmartfee', [blocks])
        fee = result['result']

        if fee is None:
            raise InvalidRPCError(result['error']['message'])

        return fee

    def get_fee_per_byte(self) -> Tuple[int, int]:
        try:
            relayfee = int(self.getnetworkinfo()['relayfee'] * 1e8)
            paytxfee = int(self.getwalletinfo()['paytxfee'] * 1e8)

        except InvalidRPCError:
            raise GetFeeError('Can\'t get fee amount!')

        if paytxfee != 0:
            maxfee = paytxfee

            if relayfee > maxfee:
                maxfee = relayfee

            return maxfee, relayfee

        try:
            usefee = int(self.estimatesmartfee()['feerate'] * 1e8)

            if relayfee > usefee:
                usefee = relayfee

            return usefee, relayfee

        except:
            pass

        print('Warning: falling back to mempool relay fee policy')
        return relayfee, relayfee

def make_coin_data(coin: str) -> Tuple[int, Coind]:
    os_name = platform.system()
    low = coin.lower()
    path = get_path()

    conf_path = '/' + low + '.conf'
    if "Testnet" in coin:
        low, testnet = low.split()
        conf_path = '/' + testnet + '/' + low + '.conf'
        with open(resource_path('coins', low + '_' + testnet + '.json')) as f:
            coin_json = json.loads(f.read())

    else:
        with open(resource_path('coins', low + '.json')) as f:
            coin_json = json.loads(f.read())

    if 'path' in coin_json:
        conf_full_path = os.path.expanduser(coin_json['path'][os_name])

    else:
        if os_name == 'Linux':
            conf_full_path = path + "." + low + conf_path

        else:
            conf_full_path = path + coin + conf_path

    def make_conf():
        with open(conf_full_path, mode='w') as f:
            config = {
                'server': 1,
                'rpcallowip': '127.0.0.1',
                'rpcport': coin_json['port'],
                'rpcuser': 'user',
                'rpcpassword': 'pass',
            }

            for key in config:
                line = '{}={}\n'.format(key, config[key])
                f.write(line)

        raise RestartWallet('Please restart coind or coin-qt')

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

    sign_wallet = False
    tx_ver = 2
    ver_id = 0

    if 'tx_ver' in coin_json:
        tx_ver = coin_json['tx_ver']

    if 'ver_id' in coin_json:
        ver_id = coin_json['ver_id']

    if 'sign_wallet' in coin_json:
        sign_wallet = coin_json['sign_wallet']

    coind = Coind(coin_json['name'], coin_json['unit'], coin_json['p2pkh'], coin_json['p2sh'],
                    coin_json['bech32_hrp'], port, user, pwd, sign_wallet, tx_ver, ver_id)

    return coin_json['req_ver'], coind
