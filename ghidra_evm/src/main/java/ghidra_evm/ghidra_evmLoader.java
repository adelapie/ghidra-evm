/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra_evm;

import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Simple loader that triggers the Ethereum VM processor definitions when the extension is evm.
 */
public class ghidra_evmLoader extends AbstractLibrarySupportLoader {

	boolean isEVM = false;
	boolean isEVM_h = false; 
	
	@Override
	public String getName() {
		return "EVM bytecode loader";
	}
	
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		this.isEVM = provider.getName().endsWith(".evm");
		this.isEVM_h = provider.getName().endsWith(".evm_h");
		
		if (this.isEVM || this.isEVM_h) {
            loadSpecs.add(new LoadSpec(this, 0,
                    new LanguageCompilerSpecPair("evm:BE:64:default", "default"), true));
		}

		return loadSpecs;
	}

	/* Mainly based on The Ghidra Book, Eagle et al. pp. 389 */
	
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		
		FlatProgramAPI flatAPI = new FlatProgramAPI(program);
		try {
			if (this.isEVM) {
				monitor.setMessage("EVM code: Starting loading");
				Address start_addr = flatAPI.toAddr(0x0);
				MemoryBlock block = flatAPI.createMemoryBlock("ram", start_addr, provider.readBytes(0, provider.length()), false);

				block.setRead(true);
				block.setWrite(true);
				block.setExecute(true);
		
				flatAPI.addEntryPoint(start_addr);
				monitor.setMessage("EVM code: Completed loading");
			} else if (this.isEVM_h) {
				monitor.setMessage("EVM code: Starting loading");				
				
				CharSequence provider_char_seq =
						new String(provider.readBytes(0, provider.length()), "UTF-8");
				Pattern p = Pattern.compile("[0-9a-fA-F]{2}");
				Matcher m = p.matcher(provider_char_seq);				
				int match_count = 0;
				while (m.find()) { match_count++;}
				m.reset();
				
				byte[] evm_byte_code_hex = new byte[match_count];
				int i = 0;
				while (m.find()) {
					String hex_digits = m.group();
					evm_byte_code_hex[i++] = (byte)Integer.parseInt(hex_digits, 16);
				}			
				
				Address start_addr = flatAPI.toAddr(0x0);
				MemoryBlock block =
						flatAPI.createMemoryBlock("ram", start_addr, evm_byte_code_hex, false);

				block.setRead(true);
				block.setWrite(true);
				block.setExecute(true);
		
				flatAPI.addEntryPoint(start_addr);
				monitor.setMessage("EVM code: Completed loading");
			} else {
				throw new IOException("Failed to load EVM code");
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new IOException("Failed to load EVM code");
		}
	}
	
	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}
}
