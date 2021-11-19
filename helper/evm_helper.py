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
evm_helper.py helps Ghidra (via ghidra-bridge) to
identify jumps and functions. Then, it instructs Ghidra to 
analyze and disassemble evm code.
"""

import ghidra_bridge
import pprint
import sys
import binascii
from tqdm import tqdm
from evm_cfg_builder.cfg import CFG

JUMP_TABLE_WORD_SIZE = 4

print(
    """\
       _     _     _                                      
  __ _| |__ (_) __| |_ __ __ _        _____   ___ __ ___  
 / _` | '_ \| |/ _` | '__/ _` |_____ / _ \ \ / / '_ ` _ \ 
| (_| | | | | | (_| | | | (_| |_____|  __/\ V /| | | | | |
 \__, |_| |_|_|\__,_|_|  \__,_|      \___| \_/ |_| |_| |_| v.0.1
 |___/                                                    
"""
)


if len(sys.argv) != 2:
    print("Usage: python(3) evm_helper.py input.[evm | evm.h]")
    exit(0)

print("[*] Parsing bytecode...")

filename_input = sys.argv[1]

if filename_input.endswith(".evm"):
    with open(filename_input, "rb") as f:
        evm_code = f.read()
    print(binascii.hexlify(evm_code))
elif filename_input.endswith(".evm_h"):
    with open(filename_input, "r") as f:
        evm_code = f.read()
        print(evm_code)
else:
    print("[!] Imposible to read bytecode")
    exit(0)

b = ghidra_bridge.GhidraBridge(
    namespace=globals(), response_timeout=1000
)  # creates the bridge and loads the flat API into the global namespace

tid = currentProgram.startTransaction("ghidrda evm")

memory = currentProgram.getMemory()
ram = memory.getBlock("ram")
addr = ram.getStart()
size = ram.getSize()

print("[*] Setting analysis options....")

setAnalysisOption(currentProgram, "Embedded Media", "false")
setAnalysisOption(currentProgram, "ASCII Strings", "false")
setAnalysisOption(currentProgram, "Create Address Tables", "false")

print("[*] Creating CFG...")
cfg = CFG(evm_code)

for basic_block in cfg.basic_blocks:
    print(
        "{} -> {}".format(
            basic_block,
            sorted(basic_block.all_outgoing_basic_blocks, key=lambda x: x.start.pc),
        )
    )

print("[*] Resolving jumps...")
evm_jump_table = memory.getBlock("evm_jump_table")
addr = evm_jump_table.getStart()

for basic_block in cfg.basic_blocks:
    if not basic_block.all_outgoing_basic_blocks:
        continue

    # Iterate over every outgoing basic block from the current basic block
    for out_block in basic_block.all_outgoing_basic_blocks:
        if (out_block.start.pc - 1) != basic_block.end.pc:
            jump_addr_list = out_block.start.pc.to_bytes(
                JUMP_TABLE_WORD_SIZE, byteorder="little"
            )
            evm_jump_table.putBytes(
                addr.add(JUMP_TABLE_WORD_SIZE * basic_block.end.pc), jump_addr_list
            )
            from_addr = currentProgram.addressFactory.getAddress(
                "%s" % basic_block.end.pc
            )
            to_addr = currentProgram.addressFactory.getAddress(
                "%s" % out_block.start.pc
            )

            print(f"Adding xref from {from_addr} -> {to_addr}")
            addInstructionXref(
                from_addr,
                to_addr,
                -1,
                ghidra.program.model.symbol.FlowType.COMPUTED_JUMP,
            )


print("[*] Exploring functions...")
for function in sorted(cfg.functions, key=lambda x: x.start_addr):
    print("\tFound function {}".format(function.name))

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

# For some reason Ghidra doesn't disassemble all the bytes in the listing view
# even though they contain xref's. The following is a hack to fix that
addr = currentProgram.addressFactory.getAddress("0x0")
while True:
    next_undef = getUndefinedDataAfter(addr)
    if next_undef is None:
        break

    addr = next_undef.getAddress()
    disassemble(addr)

currentProgram.endTransaction(tid, True)
