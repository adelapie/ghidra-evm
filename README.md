
# Ghidra EVM Module

ghidra-evm is a ghidra loader and plugin to reverse engineering Ethereum VM
(EVM) bytecode. This version uses the Ghidra 9.1.2 API. It relies on
the crytic evm_cfg_builder library (https://github.com/crytic/evm_cfg_builder)
to assist Ghidra in the CFG generation process. ghidra-evm consists of:
- A loader that parses hex code and byte code in .evm and .evm_h files.
- The SLEIGH definition of the EVM instruction set taking into account the
limitations of Ghidra (See Notes and limitations).
- A python3 script that uses evm_cfg_builder and ghidra_bridge in order to
assist ghidra generating the CFG and exploring the function properties.

## Installation instructions

- Install ghidra_bridge, following the instructions at https://github.com/justfoxing/ghidra_bridge
- Install the crytic evm_cfg_builder library, following the instructions at https://github.com/crytic/evm_cfg_builder
- Install the last ghidra-evm release file at ghidra_evm/dist/:
	- Open ghidra
	- File -> Install Extensions
	- Click on '+' and select the zip file e.g. ghidra_9.1.2_PUBLIC_20201102_ghidra_evm.zip
	- Click OK 
	- Restart Ghidra

## Utilization

ghidra-evm detects EVM bytecode in files with extension .evm and .evm_h. The
latter being generated via solc using the --bin and --bin-runtime options.
On the other hand, EVM bytecode can be encoded in binary in a .evm file
without any magic number of tags. Hex code can be converted  to a .evm file via python using for
instance https://raw.githubusercontent.com/crytic/ethersplay/master/utils/convert_bytecode.py.

- Launch ghidra, create a new project and import a .evm file. You can use the examples available at
  examples/

![main](media/1.png)

- Press OK and open the evm file in CodeBrowser
- Click No to Analyze
- Launch  ghidra_bridge_server_background.py

![script](media/2.png)

- Run evm_helper.py with the byte code file as argument. This script will fill the jump table of the contract and explore the functions, thus creating the CFG using the
  crytic evm_cfg_builder library.

```
       _     _     _                                      
  __ _| |__ (_) __| |_ __ __ _        _____   ___ __ ___  
 / _` | '_ \| |/ _` | '__/ _` |_____ / _ \ \ / / '_ ` _ \ 
| (_| | | | | | (_| | | | (_| |_____|  __/\ V /| | | | | |
 \__, |_| |_|_|\__,_|_|  \__,_|      \___| \_/ |_| |_| |_| v.0.1
 |___/                                                    

Usage: python(3) evm_helper.py input.[evm | evm.h]
```

- You can now explore the CFG, the functions and their properties as well as the disassemble code.

![demo1](media/main1.png)
![demo2](media/main2.png)

### Notes and limitations

- The CFG is created according to evm_cfg_builder, this means that mainly
the JUMP and JUMPI instructions are utilized. A jump table of 32x32 is
utilized to detect and show branches in the disassembly and control flow windows.
- ghidra has not been designed to deal with architectures of wordsizes >
64-bit. That means that supporting long instructions such as PUSH32 in
SLEIGH should be done via dedicated memory structures. 

### TODO

- Implement memory structures for dealing with instructions having
large operands such as PUSH32.
- Improve the SLEIGH definitions of complex instructions to aid
the decompilation process.
- Implement the storage functionality of Ethereum.





 


