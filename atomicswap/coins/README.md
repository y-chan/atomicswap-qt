# atomicswap-qt coins folder

## What is this folder?
This folder contains coin file(json).

## Add coins
If you want add coin to atomicswap-qt, you can pull request.
I present the procedure.
* 1, Add to \<coin name\>.json
  * json params explanation  
    example json:
    ```
    {
      "name": "Bitcoin",
      "unit": "BTC",
      "p2pkh": 0,
      "p2sh": 5,
      "bech32_hrp": "bc",
      "req_ver": 170000,
      "port": 8332
    }
    ```
    * `name` params  
      Coin name. 
    * `unit` params  
      Coin symbol.
    * `p2pkh` params  
      Prefix of "pay to public key hash".
    * `p2sh` params  
      Prefix of "pay to script hash".
    * `bech32_hrp` params  
      Prefix of bech32 address.
    * `req_ver` params  
      The version value that needs to be "signrawtransactionwithwallet".  
      If all coin version doesn't need it, please set `99999999`.
    * `port` params  
      Please set default port number.
    * `tx_ver` params (optional)  
      Tx Version. Default is "2". If coin can't use "2", please set number.
      For example, Koto needs set "4".
    * `ver_id` params (optional)  
      Version Group Id. Koto needs this params.
    * `path` params (optional)  
      Custom coin directory path. For Example, MicroBitcoin needs this params.  
* 2, Add coin icon to this folder.
  Please add coin icon.(png or jpg)
* 3, Add coin name to coin_list
  Please add coin name to [util.py](../util.py).
