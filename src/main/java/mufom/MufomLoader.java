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
package mufom;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;
import mufom.MufomHeader.MufomData;
import mufom.MufomHeader.MufomDebugInformation;
import mufom.MufomHeader.MufomExternal;
import mufom.MufomHeader.MufomSectionDefinition;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class MufomLoader extends AbstractProgramWrapperLoader {

	private Program program;
	private Memory memory;
	private Listing listing;
	private MessageLog log;
	private MufomHeader curr;

	@Override
	public String getName() {
		return MufomHeader.getName();
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		MufomHeader mufom = new MufomHeader(provider, null);
		if (mufom.valid()) {
			List<QueryResult> results =
					QueryOpinionService.query(getName(), mufom.machine(), null);
			for (QueryResult result : results) {
				boolean add = true;
				if (mufom.is_little() && result.pair.getLanguageDescription().getEndian() != Endian.LITTLE) {
					add = false;
				}
				if (mufom.is_big() && result.pair.getLanguageDescription().getEndian() != Endian.BIG) {
					add = false;
				}
				if (add) {
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, 0, true));
			}
		}

		return loadSpecs;
	}

	private AddressSpace getDefaultAddressSpace() {
		return program.getAddressFactory().getDefaultAddressSpace();
	}
	
	private void createDataTypes() {
		MufomDebugInformation asw4 = curr.asw4;
		DataTypeManager dtm = program.getDataTypeManager();
		
		while (null != asw4) {
			for (MufomTY ty : asw4.types) {
				switch ((int) ty.ty_code) {
				case MufomType.MUFOM_CT_STRUCTURE:
					dtm.addDataType(ty.type_structure.struct, null);
					break;
				default:
					break;
				}
			}
			
			asw4 = asw4.next;
		}		
	}
	
	private void createSymbols() throws InvalidInputException {
		SymbolTable symbolTable = program.getSymbolTable();
		MufomDebugInformation asw4 = curr.asw4;
		Address addr = null;

		while (asw4 != null) {
			for (MufomSymbol symbol : asw4.symbols) {
				if (symbol.getAddress() < 0 || symbol.getName() == null) {
					//TODO  which fail this
					continue;
				}
				addr = getDefaultAddressSpace().getAddress(symbol.getAddress());
				if (null != addr) {
					symbolTable.createLabel(addr, symbol.getName(), null, SourceType.IMPORTED);
				}
			}
			asw4 = asw4.next;
		}
	}
	
	private void createLabels() throws InvalidInputException {
		SymbolTable symbolTable = program.getSymbolTable();
		MufomExternal asw3 = curr.asw3;
		Address addr = null;

		while (asw3 != null) {
			addr = getDefaultAddressSpace().getAddress(asw3.getAddress());
			if (null != addr) {
				symbolTable.createLabel(addr, asw3.getName(), null, SourceType.IMPORTED);
			}
			asw3 = asw3.next;
		}
	}

	private void fillSections() throws IOException, MemoryAccessException {
		MufomData asw5 = curr.asw5;
		Address addr = null;
		while (asw5 != null) {
			long address = asw5.getSectionAddress();
			long offset = asw5.getDataOffset();
			long length = asw5.getDataLength();

			if (address > 0) {
				addr = getDefaultAddressSpace().getAddress(address);
			}
			
			if (memory.contains(addr, addr.add(length - 1))) {
				byte[] data = curr.reader.readByteArray(offset, (int) length);
				program.getMemory().setBytes(addr, data);
				addr = addr.add(length);
			}
			asw5 = asw5.next;
		}
	}

	private void createSections(MessageLog log) throws MemoryBlockException, LockException, NotFoundException {
		MufomSectionDefinition asw2 = curr.asw2;
		MemoryBlock blockStart;
		MemoryBlock blockEnd;
		MemoryBlock blockNew;
		Address addr = null;
		long address;
		long len;

		while (asw2 != null) {
			address = asw2.getBaseAddress();
			len = asw2.getSectionLength();
			if (address >= 0 && len > 0) {
				addr = getDefaultAddressSpace().getAddress(address);
	
				blockNew = null;
				blockStart = memory.getBlock(addr);
				blockEnd = memory.getBlock(addr.add(len - 1));
	
				// There are attributes that describe if some of this should happen, but depending on when
				// the section gets added that logic may be difficult to tell.
				if (null == blockStart && null == blockEnd) {
					// No section contains this address, create a new block
					blockNew = MemoryBlockUtils.createInitializedBlock(program, false, asw2.getName(), addr, len,
							"Section: 0x" + Long.toHexString(asw2.getSectionIndex()), null, true, true, true, log);
					//TODO  join if next to each other?
				} else if (null == blockStart && null != blockEnd) {
					// blockNew overlaps the end of a section
					len = addr.subtract(blockEnd.getEnd().add(1));
					addr = blockEnd.getEnd().add(1);
					blockNew = MemoryBlockUtils.createInitializedBlock(program, false, asw2.getName(), addr, len,
							"Section: 0x" + Long.toHexString(asw2.getSectionIndex()), null, true, true, true, log);
					memory.join(blockEnd, blockNew);
				} else if (null != blockStart && null == blockEnd) {
					// blockNew overlaps the start of a section
					len = blockStart.getStart().subtract(addr);
					blockNew = MemoryBlockUtils.createInitializedBlock(program, false, asw2.getName(), addr, len,
							"Section: 0x" + Long.toHexString(asw2.getSectionIndex()), null, true, true, true, log);
					memory.join(blockNew, blockStart);
				} else if (null != blockStart && null != blockEnd) {
					// blockNew is inside a section
				}
			}
			asw2 = asw2.next;
		}
	}
	
	private void load(MufomHeader mufom,Program program, TaskMonitor monitor,
			MessageLog log) throws IOException, InvalidInputException, MemoryAccessException, LockException, NotFoundException {
		this.program = program;
		this.memory = program.getMemory();
		this.listing = program.getListing();
		this.curr = mufom;
		this.log = log;

		createDataTypes();
		createSections(log);
		fillSections();
		createLabels();
		createSymbols();
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		MufomHeader mufom = new MufomHeader(provider, msg -> log.appendMsg(msg));
		try {
			load(mufom, program, monitor, log);
		} catch (InvalidInputException e) {
			//
		} catch (MemoryAccessException e) {
			//
		} catch (NotFoundException e) {
			//
		} catch (LockException e) {
			//
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
