#!/usr/bin/env python

"""
search_codecopy.py analyzes EVM creation code and
finds the function_selector and the methods of the
contract in the runtime code part.
"""

import ghidra_bridge
import pprint
import sys
import binascii
from tqdm import tqdm
from evm_cfg_builder.cfg import CFG

# constants

DANGEROUS_INSTRUCTIONS = ["CALL", "SELFDESTRUCT", "CALLCODE", "DELEGATECALL"]

# main

print("""\
       _     _     _                                      
  __ _| |__ (_) __| |_ __ __ _        _____   ___ __ ___  
 / _` | '_ \| |/ _` | '__/ _` |_____ / _ \ \ / / '_ ` _ \ 
| (_| | | | | | (_| | | | (_| |_____|  __/\ V /| | | | | |
 \__, |_| |_|_|\__,_|_|  \__,_|      \___| \_/ |_| |_| |_| v.0.1
 |___/                                                    
""")

# creates the bridge and loads the flat API into the global namespace
b = ghidra_bridge.GhidraBridge(namespace=globals(), response_timeout=1000) 

tid = currentProgram.startTransaction("ghidrda evm")

memory = currentProgram.getMemory()

ram = memory.getBlock("ram")
ram_size = ram.getSize()
ram_addr = ram.getStart()

print("[*] Reading RAM:", ram_size, "bytes", "at", ram_addr)

i = getInstructionAt(ram_addr)

print("[*] Searching dangerous instructions...")

while True: 

  ins = i.getMnemonicString()
  if ins in DANGEROUS_INSTRUCTIONS:
   print("\t[!]", ins, "found at", i.getAddress())
   createLabel(i.getAddress(), ins+"_"+str(i.getAddress()), True)
  i = i.getNext()
  if i is None:
   break

currentProgram.endTransaction(tid,True)
