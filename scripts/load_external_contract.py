#!/usr/bin/env python
"""
load_external_contract.py downloads a contract byte code from
the blockchain and write it into a .evm_h file.
"""
import urllib.request
import urllib.parse
import argparse
import json

def main():
    parser = argparse.ArgumentParser()
    
    parser.add_argument("api_key", help="etherscan API key")
    parser.add_argument("contract_address", help="contract address")
    parser.add_argument("-v", "--verbosity", action="count", default=0)
    
    args = parser.parse_args()
    
    API_KEY = args.api_key
    CONTRACT_ADDR = args.contract_address

    URL_ROPSTEN= 'https://api-ropsten.etherscan.io/api?module=proxy&action=eth_getCode&address='.strip() + CONTRACT_ADDR + "&tag=latest&apikey=".strip() + API_KEY.strip()
    URL_MAIN= 'https://api.etherscan.io/api?module=proxy&action=eth_getCode&address='.strip() + CONTRACT_ADDR + "&tag=latest&apikey=".strip() + API_KEY.strip()

    print("[*] Downloading contract byte code...")

    try: 
        request = urllib.request.urlopen(URL_ROPSTEN)
        data = json.load(request)

        if 'result' in data:
            if (args.verbosity):
                print(data['result'])
            print("[*] Writing contract byte code into {}".format(args.contract_address.strip() + ".evm_h"))
            contract_file = open(args.contract_address.strip() + ".evm_h", "w")

            if (data['result'].startswith("0x")):
                contract_file.write(data['result'][2:])
            else:
                contract_file.write(data['result'])

            contract_file.close()        

    except urllib.error.URLError as e:
        print(e.reason) 

if __name__ == "__main__":
    main()
    

