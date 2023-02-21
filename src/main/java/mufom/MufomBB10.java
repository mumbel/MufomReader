/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License; Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing; software
 * distributed under the License is distributed on an "AS IS" BASIS;
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND; either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package mufom;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Calendar;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;

/*
 * An assembler debugging information block.
 * 
 * { [BB5] [[NN] ATN ASN] } [BB10]
 */
public class MufomBB10 extends MufomRecord {
	public static final int record_type = MufomType.MUFOM_DBLK_ASMSC;
	public static final String NAME = "BB10";
	public long record_offset = -1;
	public String source_filename = null;
	public long tool_type = -1;
	public String version = null;
	public Calendar date;
	public ArrayList<MufomSymbol> symbols = new ArrayList<MufomSymbol>();
	
	MufomBB bb = null;
	MufomNN nn = null;
	MufomASN asn = null;
	MufomATN atn = null;

	private void print() {
		String msg = NAME + "; " + source_filename + " " + tool_type;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomBB10(BinaryReader reader) throws IOException {
		this(reader, null);
	}

	public MufomBB10(BinaryReader reader, DataTypeManager dtm) throws IOException {
		Msg.trace(this, String.format("%08x ENTER %s", reader.getPointerIndex(), NAME));
		
		//TODO  Assembly Module Block Begin (BB10)
		//TODO      Compiler Generated Global/External Variables (NH, ATK16, ASK)
		//TODO      Compiler Generated Local Variables (NH, ATK16, ASK)
		//TODO      Assembler Section Block Begin (BB11)
		//TODO      Assembler Section Block End (BE11)
		//TODO      Assembler Section Block Begin (BB11) // ... one for each module?
		//TODO      Assembler Section Block End (BE11)
		//TODO  Assembly Module Block End (BE10)
		//TODO  Assembly Module Block Begin (BB10)
		//TODO      Global/Extern Variables (KN, ATN19, ASN)
		//TODO      Local Variables (KK, ATN19, ASN)
		//TODO      Assembler Section Block Begin (BB11)
		//TODO      Assembler Section Block End (BE11)
		//TODO      Assembler Section Block Begin (BB11) // ... one for each module?
		//TODO      Assembler Section Block End (BE11)	
		//TODO  Assembly Module Block End (BE10)
		

		source_filename = read_id(reader);
		
		String zero = read_id(reader);
		if (zero.length() != 0) {
			Msg.info(this, "Bad zero");
			throw new IOException();
		}

		tool_type = read_int(reader);
		
		String version_string = read_opt_id(reader);
		
		long x1 = read_opt_int(reader);
		if (-1 != x1) {
			long x2 = read_opt_int(reader);
			if (-1 != x2) {
				long x3 = read_opt_int(reader);
				if (-1 != x3) {
					long x4 = read_opt_int(reader);
					if (-1 != x4) {
						long x5 = read_opt_int(reader);
						if (-1 != x5) {
							long x6 = read_opt_int(reader);
						}
					}
				}
			}
		}
		
		MufomRecord record = MufomRecord.readRecord(reader);

		//TODO  can these two loops be figured out or does it matter
		Msg.trace(this, "Start NN/ATN/ASN  compiler global");
		do {
			if (record instanceof MufomNN) {
				nn = (MufomNN) record;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomATN) {
				atn = (MufomATN) record;
				record = MufomRecord.readRecord(reader);
			} else {
				break;
			}			
			if (record instanceof MufomASN) {
				asn = (MufomASN) record;
				record = MufomRecord.readRecord(reader);
			}
			symbols.add(new MufomSymbol(nn.symbol_name, asn.symbol_name_value, atn.attribute_definition, atn.symbol_name_index));
		} while (record instanceof MufomNN || record instanceof MufomATN);

		Msg.trace(this, "Start NN/ATN/ASN  compiler local");
		do {
			if (record instanceof MufomNN) {
				nn = (MufomNN) record;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomATN) {
				atn = (MufomATN) record;
				record = MufomRecord.readRecord(reader);
			} else {
				break;
			}			
			if (record instanceof MufomASN) {
				asn = (MufomASN) record;
				record = MufomRecord.readRecord(reader);
			}
			symbols.add(new MufomSymbol(nn.symbol_name, asn.symbol_name_value, atn.attribute_definition, atn.symbol_name_index));
		} while (record instanceof MufomNN || record instanceof MufomATN);

		Msg.trace(this, "Start assembler sections");
		while (record instanceof MufomBB) {
			MufomBB bb11 = (MufomBB) record;

			if (MufomType.MUFOM_DBLK_MODSEC == bb11.begin_block) {
				symbols.addAll(bb11.bb11.symbols);
				record = MufomRecord.readRecord(reader);
			} else {
				Msg.info(this, "Expected bb11, but " + bb11.begin_block);
				throw new IOException();
			}
		}

		Msg.trace(this, "Start NN/ATN/ASN  global");
		do {
			if (record instanceof MufomNN) {
				nn = (MufomNN) record;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomATN) {
				atn = (MufomATN) record;
				record = MufomRecord.readRecord(reader);
			} else {
				break;
			}			
			if (record instanceof MufomASN) {
				asn = (MufomASN) record;
				record = MufomRecord.readRecord(reader);
			}
			symbols.add(new MufomSymbol(nn.symbol_name, asn.symbol_name_value, atn.attribute_definition, atn.symbol_name_index));
		} while (record instanceof MufomNN || record instanceof MufomATN);

		Msg.trace(this, "Start NN/ATN/ASN  local");
		do {
			if (record instanceof MufomNN) {
				nn = (MufomNN) record;
				record = MufomRecord.readRecord(reader);
			}
			if (record instanceof MufomATN) {
				atn = (MufomATN) record;
				record = MufomRecord.readRecord(reader);
			} else {
				break;
			}			
			if (record instanceof MufomASN) {
				asn = (MufomASN) record;
				record = MufomRecord.readRecord(reader);
			}
			symbols.add(new MufomSymbol(nn.symbol_name, asn.symbol_name_value, atn.attribute_definition, atn.symbol_name_index));
		} while (record instanceof MufomNN || record instanceof MufomATN);
		
		if (record instanceof MufomLN) {
			Msg.trace(this, String.format("%08x BE %s", reader.getPointerIndex(), NAME));
			record.reset(reader);
			MufomBE be10 = new MufomBE(reader, record_type);
		}  else {
			Msg.info(this, "bad be 10");
			throw new IOException();
		}

		Msg.trace(this, String.format("%08x EXIT %s", reader.getPointerIndex(), NAME));
	}
}
