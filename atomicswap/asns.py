# Copyright (c) 2019-2020 The atomicswap-qt developers
# Copyright (c) 2020 The Atomic Swap Network Developers
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

from typing import Tuple, Dict, Optional

import requests


class ASNSConnect:
    def __init__(self):
        self.endpoint = "http://192.168.1.189:8000/"
        assert self.connection_check(), "Failed connect ASNS server."

    def make_get_requests(self, path: str) -> Dict:
        try:
            return requests.get(f"{self.endpoint}{path}").json()
        except Exception:
            return {
                "error": "{} backend is down or not responding".format(self.endpoint)
            }

    def make_post_requests(self, path: str, data: Dict) -> Dict:
        try:
            return requests.post(f"{self.endpoint}{path}", json=data).json()
        except Exception:
            return {
                "error": "{} backend is down or not responding".format(self.endpoint)
            }

    def connection_check(self) -> bool:
        result = self.make_get_requests("")
        if result.get("message") == "This server is working.":
            return True
        return False

    def get_token(self) -> str:
        result = self.make_get_requests("get_token/")
        return result["token"]

    def register_swap(
            self,
            token: str,
            want_currency: str,
            want_amount: int,
            send_currency: str,
            send_amount: int,
            receive_address: str
    ) -> Optional[str]:
        data = {
            "token": token,
            "wantCurrency": want_currency,
            "wantAmount": want_amount,
            "sendCurrency": send_currency,
            "sendAmount": send_amount,
            "receiveAddress": receive_address
        }
        result = self.make_post_requests("register_swap/", data)
        return result.get("error")

    def get_swap_list(self) -> Dict:
        result = self.make_get_requests("get_swap_list/")
        return result["data"]

    def initiate_swap(self, token: str, selected_swap: str, receive_address: str) -> Optional[str]:
        data = {
            "token": token,
            "selectedSwap": selected_swap,
            "receiveAddress": receive_address
        }
        result = self.make_post_requests("initiate_swap/", data)
        return result.get("error")

    def get_initiator_info(self, token: str) -> Dict:
        result = self.make_post_requests("get_initiator_info/", {"token": token})
        return result

    def participate_swap(self, token: str, raw_tx: str) -> Optional[str]:
        data = {
            "token": token,
            "rawTransaction": raw_tx
        }
        result = self.make_post_requests("participate_swap/", data)
        return result.get("error")

    def get_swap_status(self, token_hash: str) -> str:
        result = self.make_get_requests(f"get_swap_list/{token_hash}/")
        return result["swapStatus"]

    def redeem_swap(self, token: str, raw_tx: str, selected_swap: str) -> Optional[str]:
        data = {
            "token": token,
            "rawTransaction": raw_tx,
            "selectedSwap": selected_swap
        }
        result = self.make_post_requests("redeem_swap/", data)
        return result.get("error")

    def get_redeem_token(self, token: str) -> str:
        result = self.make_post_requests("get_redeem_token/", {"token": token})
        return result["token"]

    def complete_swap(self, token: str, raw_tx: str) -> Optional[str]:
        data = {
            "token": token,
            "rawTransaction": raw_tx
        }
        result = self.make_post_requests("complete_swap/", data)
        return result.get("error")
