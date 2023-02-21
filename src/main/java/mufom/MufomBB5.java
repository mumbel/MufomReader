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
 * A source file line number block.
 * 
 * { [BB5] [[NN] ATN ASN] } [BB10]
 * 
 * {$F8}{$05}{0}{Id}
 */
public class MufomBB5 extends MufomRecord {
	public static final int record_type = MufomType.MUFOM_DBLK_SLINE;
	public static final String NAME = "BB5";
	public String source_filename = null;

	public ArrayList<MufomSymbol> symbols = new ArrayList<MufomSymbol>();

	private void print() {
		String msg = NAME + ": " + source_filename;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomBB5(BinaryReader reader) throws IOException {
		this(reader, null);
	}

	public MufomBB5(BinaryReader reader, DataTypeManager dtm) throws IOException {
		
		//TODO  Source File Block Begin (BB5)
		//TODO      NN,ASN,ATN, line numbers in source
		//TODO  Source File Block End (BE5)
		
		source_filename = read_id(reader);
		
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

		if (record instanceof MufomLN) {
			record.reset(reader);
			MufomBE be = new MufomBE(reader, record_type);
		} else {
			Msg.info(this, "bad BE 5");
			throw new IOException();
		}
	}
}
