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
import ghidra.util.Msg;

/*
 * A global subprogram.
 * 
 * {[BB6] ([NN] ATN) or (NN ATN[ASN]) }
 * 
 * {$F8}{$04}{0}{Id}{0}{n3}{n4}
 */
public class MufomBB4 extends MufomRecord {
	public static final int record_type = MufomType.MUFOM_DBLK_GFUNC;
	public static final String NAME = "BB4";
	public String function_name = null;
	public long type_index = -1;
	public long code_block_address = -1;
	public long n5 = -1;

	public ArrayList<MufomSymbol> symbols = new ArrayList<MufomSymbol>();

	private void print() {
		String msg = NAME + ": " + function_name + " " + type_index + " " + Long.toHexString(code_block_address) + " " + n5;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomBB4(BinaryReader reader) throws IOException {
		Msg.info(this, String.format("%08x ENTER %s", reader.getPointerIndex(), NAME));

		function_name = read_id(reader);

		//TODO  is this always 0x0?
		if (0 != read_int(reader)) {
			Msg.info(this, "Bad stack space");
			throw new IOException();
		}

		type_index = read_int(reader);

		code_block_address = read_int(reader);

		n5 = read_opt_int(reader);

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
			Msg.info(this, "bad BE 4");
			throw new IOException();
		}
	}
}
