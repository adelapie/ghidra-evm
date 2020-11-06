
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
- A collection of scripts that help to reverse engineering different aspects
of a smart contract:

| Script | Description |
| --- | --- |
| [search_codecopy.py](scripts/search_codecopy.py) | When analyzing creation code in a smart contract we can only see the _dispatcher function that uses CODECOPY in order to write the run time code into memory. This script looks for useful CODECOPY instructions and finds the smart contract methods hidden in the runtime part of the contract. |
| [search_dangerous_instructions.py](scripts/search_dangerous_instructions.py) | Instructions such as CALL, CALLCODE, SELFDESTRUCT and DELEGATECALL can sometimed be abused to transfer funds to another contract. This script finds them and creates a label for each occurrence.|
| [load_external_contract.py](scripts/load_external_contract.py) | Downloads smart contract byte code from the blockchain into a .evm_h file that can be loaded into ghidra-evm |

## Installation instructions

- Install ghidra_bridge, following the instructions at https://github.com/justfoxing/ghidra_bridge
- Install the crytic evm_cfg_builder library, following the instructions at https://github.com/crytic/evm_cfg_builder
- Install the last ghidra-evm release file at ghidra_evm/dist/:
	- Open ghidra
	- File -> Install Extensions
	- Click on '+' and select the zip file e.g. ghidra_9.1.2_PUBLIC_20201102_ghidra_evm.zip
	- Click OK 
	- Restart Ghidra

## Tutorials

| Tutorial | Description |
| --- | --- |
| [Utilization](tutorials/00_utilization.md) | Simple utilization instructions with test.evm |
| [Analyzing creation bytecode](tutorials/01_codecopy.md) | Using search_codecopy.py to analyze creation code and finding hidden methods |
| [Looking for dangerous instructions](tutorials/03_dangerous.md) | Using search_dangerous_instructions.py to analyze a SELFDESTRUCT ocurrence |
| [Downloading smart contract bytecode from the blockchain into Ghidra](tutorials/04_external.md) | Using load_external_contract.py to download EVM byte code from the blockchain into a .evm_h file |

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





 


