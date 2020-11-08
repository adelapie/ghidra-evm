#!/usr/bin/env python

"""
Ghidra-evm
Copyright (C) 2020 - Antonio de la Piedra

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

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
