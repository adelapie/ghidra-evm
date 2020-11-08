
## Downloading smart contract bytecode from the blockchain into Ghidra

Sometimes you want to analyze a running smart contract in the blockchain. In
this tutorial we download a deployed contract by the ethernaut CTF (0x7cc7F0B96CFC9019a3827A44adfF581a64624Bd5) in the
Ropsten network. 

You will need to obtain an API key at etherscan.io first. Then, we can use
[load_external_contract.py](scripts/load_external_contract.py) to download
it into an evm_h file:

```
$ python3 scripts/load_external_contract.py $(YOUR_API_KEY_HERE) 0x7cc7F0B96CFC9019a3827A44adfF581a64624Bd5
[*] Downloading contract byte code...
[*] Writing contract byte code into 0x7cc7F0B96CFC9019a3827A44adfF581a64624Bd5.evm_h
```

After, you can disassemble the contents of the contract as usual in Ghidra
via ghidra-evm.

Finally, you can always use the -m switch to download a smart contract from
the main network.


