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

JUMP_TABLE_WORD_SIZE = 4

# functions

def read_ram(ram, addr, size):
 print("[*] Reading RAM:", size, "bytes", "at", addr)

 addr_ram = ram.getStart().add(int(addr, 16))

 evm_code = ""

 for i in tqdm(range(0, int(copy_size, 16) - 1)):
  ram_byte = ram.getByte(addr_ram.add(i))
  evm_code = evm_code + "{:02x}".format(ram_byte & 0xff)
            
 print(evm_code)

 return evm_code

""" returns cfg """

def fill_jump_table(evm_code, evm_jump_table, copy_addr):

 print("[*] Creating CFG...")
 cfg = CFG(evm_code)

 print("[*] Resolving jumps...")
 addr = evm_jump_table.getStart()

 for basic_block in cfg.basic_blocks:
  if (basic_block.all_outgoing_basic_blocks):
   print(basic_block)
   print("Finishes at: ", hex(basic_block.end.pc + int(copy_addr, 16)))
   if (len(basic_block.all_outgoing_basic_blocks) == 2):  # JUMPI creates 2 branches
     for out_block in basic_block.all_outgoing_basic_blocks:
      if ((out_block.start.pc - 1) != basic_block.end.pc):
       print("\tJUMPI to: ", hex(out_block.start.pc))
       jmp_in_addr = out_block.start.pc
       jmp_in_addr += int(copy_addr, 16)
       jump_addr_list = jmp_in_addr.to_bytes(JUMP_TABLE_WORD_SIZE, byteorder="little")
                    
       jmp_out_addr = basic_block.end.pc
       jmp_out_addr += int(copy_addr, 16)
                    
       evm_jump_table.putBytes(addr.add(JUMP_TABLE_WORD_SIZE*jmp_out_addr), jump_addr_list)
   else:
    print("\tJUMP to:", hex(basic_block.all_outgoing_basic_blocks[0].start.pc + int(copy_addr, 16)))
    jmp_in_addr = basic_block.all_outgoing_basic_blocks[0].start.pc
    jmp_in_addr += int(copy_addr, 16)
    jump_addr_list = jmp_in_addr.to_bytes(JUMP_TABLE_WORD_SIZE, byteorder="little")

    jmp_out_addr = basic_block.end.pc
    jmp_out_addr += int(copy_addr, 16)

    evm_jump_table.putBytes(addr.add(JUMP_TABLE_WORD_SIZE*jmp_out_addr), jump_addr_list)

 return cfg  

def explore_functions(cfg, copy_addr):
 print("[*] Exploring functions...")

 for function in sorted(cfg.functions, key=lambda x: x.start_addr):
    print("\tFound function: ", function.name, "at: ", addr_ram.add(function.start_addr))
    if (function.name == "_dispatcher"):
      createFunction(addr_ram.add(function.start_addr), "function_selector")
    else:
     createFunction(addr_ram.add(function.start_addr), function.name)
    
    
    listing = currentProgram.getListing()
    codeUnit = listing.getCodeUnitAt(toAddr(function.start_addr + int(copy_addr, 16)))

    attr_list = ""

    for attr in function.attributes:
     attr_list = attr_list + " " + attr

    codeUnit.setComment(codeUnit.PRE_COMMENT, "attributes: " + attr_list)

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

print("[*] Looking for _dispatcher...")

function_list = getGlobalFunctions("_dispatcher")

memory = currentProgram.getMemory()
ram = memory.getBlock("ram")
ram_size = ram.getSize()

if (function_list):
 addr = function_list[0].getEntryPoint()

 i = getInstructionAt(addr)

 print("[*] Searching for CODECOPY operands...")

 codecopy_list = []
  
 while True: 
  codecopy_operands = []
    
  nem = i.getMnemonicString()
  if nem == "CODECOPY":
   print("\tCODECOPY found at", i.getAddress())
   j = i.getPrevious()

   # look in the last 10 instructions for the CODECOPY arguments
   
   for ins in range(1, 10):
    if (j.getMnemonicString().startswith("PUSH")):
     codecopy_operands.append(str(j.getOpObjects(0)[0]))

    j = j.getPrevious()

   # we only care about CODECOPY instructions
   # with memory offsets at 0, generally they
   # contain memory areas covered by other
   # CODECOPYs with memory offsets != 0.

   if (len(codecopy_operands) >= 3):   
    if(codecopy_operands[0] == "0x0"):
     codecopy_elem = {}
     codecopy_elem['addr'] = codecopy_operands[1]
     codecopy_elem['size'] = codecopy_operands[2]
     codecopy_list.append(codecopy_elem)   
  
  i = i.getNext()
  if i is None:
   break

for i in codecopy_list:
 copy_addr = i['addr'] 
 copy_size = i['size'] 

 evm_code = read_ram(ram, copy_addr, copy_size)
 addr_ram = ram.getStart().add(int(copy_addr, 16))
 evm_jump_table = memory.getBlock("evm_jump_table")
 cfg = fill_jump_table(evm_code, evm_jump_table, copy_addr)
 explore_functions(cfg, copy_addr)

 print("[*] Analyzing....")
 analyzeAll(currentProgram)

 print("[*] Disassemble all....")
 disassemble(ram.getStart().add(int(copy_addr, 16)))

currentProgram.endTransaction(tid,True)
