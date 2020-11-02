#!/usr/bin/env python

"""
evm_helper.py helps Ghidra (via ghidra-bridge) to
identify jumps and functions. Then, it instructs Ghidra to 
analyze and disassemble evm code.
"""

import ghidra_bridge
import pprint
import sys
from tqdm import tqdm
from evm_cfg_builder.cfg import CFG


print("""\
       _     _     _                                      
  __ _| |__ (_) __| |_ __ __ _        _____   ___ __ ___  
 / _` | '_ \| |/ _` | '__/ _` |_____ / _ \ \ / / '_ ` _ \ 
| (_| | | | | | (_| | | | (_| |_____|  __/\ V /| | | | | |
 \__, |_| |_|_|\__,_|_|  \__,_|      \___| \_/ |_| |_| |_|
 |___/                                                    
""")

b = ghidra_bridge.GhidraBridge(namespace=globals(), response_timeout=1000) # creates the bridge and loads the flat API into the global namespace

tid = currentProgram.startTransaction("ghidrda evm")

memory = currentProgram.getMemory()
ram = memory.getBlock("ram")
addr = ram.getStart()
size = ram.getSize()

print("[*] Reading RAM....")

evm_code = ""

# Is this faster ?
#array = b.remote_import("array")
#all_bytes = array.array ( 'b', '\x00'*size )
#ram.getBytes(addr, all_bytes, 0, size)
#for val in all_bytes:
#        evm_code = evm_code + "{:02x}".format(val & 0xff)

for i in tqdm(range(0, size)):
        ram_byte = ram.getByte(addr.add(i))
        evm_code = evm_code + "{:02x}".format(ram_byte & 0xff)
            
print(evm_code)

print("[*] Creating CFG...")
cfg = CFG(evm_code)

print("[*] Resolving jumps...")
evm_jump_table = memory.getBlock("evm_jump_table")
addr = evm_jump_table.getStart()

for basic_block in cfg.basic_blocks:
    if (basic_block.all_outgoing_basic_blocks):
        print(basic_block)
        print("Finishes at: ", hex(basic_block.end.pc))
        if (len(basic_block.all_outgoing_basic_blocks) == 2):  # JUMPI creates 2 branches
            for out_block in basic_block.all_outgoing_basic_blocks:
                if ((out_block.start.pc - 1) != basic_block.end.pc):
                    print("\tJUMPI to: ", hex(out_block.start.pc))
                    jump_addr_list = out_block.start.pc.to_bytes(2, byteorder="little")
                    evm_jump_table.putBytes(addr.add(basic_block.end.pc), jump_addr_list)

        else:
            print("\tJUMP to:", hex(basic_block.all_outgoing_basic_blocks[0].start.pc))
            jump_addr_list = basic_block.all_outgoing_basic_blocks[0].start.pc.to_bytes(2, byteorder="little")
            evm_jump_table.putBytes(addr.add(basic_block.end.pc), jump_addr_list)

print("[*] Exploring functions...")

for function in sorted(cfg.functions, key=lambda x: x.start_addr):
    print('\tFound function {}'.format(function.name))
    createFunction(toAddr(function.start_addr), function.name)
    listing = currentProgram.getListing()
    codeUnit = listing.getCodeUnitAt(toAddr(function.start_addr))

    attr_list = ""

    for attr in function.attributes:
        attr_list = attr_list + " " + attr

    codeUnit.setComment(codeUnit.PRE_COMMENT, "attributes: " + attr_list)

print("[*] Analyzing....")
analyzeAll(currentProgram)

print("[*] Disassemble all....")
disassemble(ram.getStart())

currentProgram.endTransaction(tid,True)



