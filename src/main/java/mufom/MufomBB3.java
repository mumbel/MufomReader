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

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;

/*
 * A module. A non-separable unit of code, usually the result of a
 * single compilation, i.e. the symbols associated with a COFF
 * .file symbol.
 * 
 * {[BB4] [BB6] NN ATN[ASN]}
 */
public class MufomBB3 extends MufomRecord {
	public static final int record_type = MufomType.MUFOM_DBLK_MSCOPE;
	public static final String NAME = "BB3";
	public String module_name = null;
	
	public ArrayList<MufomSymbol> symbols = new ArrayList<MufomSymbol>();

	private void print() {
		String msg = NAME + ": " + module_name;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomBB3(BinaryReader reader) throws IOException {
		this(reader, null);
	}

	public MufomBB3(BinaryReader reader, DataTypeManager dtm) throws IOException {

		//TODO  High Level Module Block Begin (BB3)
		//TODO      Global Variables (NN, ATN8, ASN)
		//TODO      Module-Scope Variables (NN, ATN3, ASN)
		//TODO      Module-Scope Function Block Begin (BB6)
		//TODO          Local Variables (NN, ATN, ASN)
		//TODO      Module-Scope Function Block End (BE6)
		//TODO      Global Function Block Begin (BB4)
		//TODO          Local Variables (NN, ATN, ASN)
		//TODO          Local Function Block Begin (BB6)
		//TODO              Local Variables (NN, ATN, ASN)
		//TODO          Local Function Block End (BE6)
		//TODO      Global Function Block End (BE4)
		//TODO High Level Module Block End (BE3)

		module_name = read_id(reader);

		MufomNN nn = null;
		MufomATN atn = null;
		MufomASN asn = null;
		MufomRecord record = MufomRecord.readRecord(reader);

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

		// what is this?
		if (record instanceof MufomATN) {
			atn = (MufomATN) record;
			record = MufomRecord.readRecord(reader);
		}

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

		if (record instanceof MufomBB) {
			MufomBB bb = (MufomBB) record;

			if (MufomType.MUFOM_DBLK_LFUNC == bb.begin_block) {
				symbols.addAll(bb.bb6.symbols);
				record = MufomRecord.readRecord(reader);
			}
		}

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

		if (record instanceof MufomBB) {
			MufomBB bb = (MufomBB) record;
			
			while (MufomType.MUFOM_DBLK_GFUNC == bb.begin_block) {
				symbols.addAll(bb.bb4.symbols);
				record = MufomRecord.readRecord(reader);

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

				if (!(record instanceof MufomBB)) {
					record.reset(reader);
					break;
				}
				bb = (MufomBB) record;
			}
			
			record = MufomRecord.readRecord(reader);
		}

		if (record instanceof MufomLN) {
			record.reset(reader);
			MufomBE be = new MufomBE(reader, record_type);
		} else {
			Msg.info(this, "bad BE 3");
			throw new IOException();
		}

		print();
	}
}
