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

	@Override
	public String getName() {
		return "Simple evm extension loader";
	}
	
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		if (provider.getName().endsWith(".evm")) {
            loadSpecs.add(new LoadSpec(this, 0,
                    new LanguageCompilerSpecPair("evm:BE:64:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		
		FlatProgramAPI flatAPI = new FlatProgramAPI(program);
		try {
			monitor.setMessage("EVM code: Starting loading");
			Address start_addr = flatAPI.toAddr(0x0);
			MemoryBlock block = flatAPI.createMemoryBlock("ram", start_addr, provider.readBytes(0, provider.length()), false);

			block.setRead(true);
			block.setWrite(true);
			block.setExecute(true);
		
			flatAPI.addEntryPoint(start_addr);
			monitor.setMessage("EVM code: Completed loading");
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
