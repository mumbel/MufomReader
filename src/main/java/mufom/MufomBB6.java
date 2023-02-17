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

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

/*
 * A local (static) subprogram.
 * 
 * {[BB6] ([NN] ATN) or (NN ATN[ASN]) }
 * 
 * {$F8}{$06}{0}{Id}{n2}[n3]{n4}
 */
public class MufomBB6 extends MufomRecord {
	public static final int record_type = MufomType.MUFOM_DBLK_LFUNC;
	public static final String NAME = "BB6";
	public String function_name = null;
	public long stack_space = -1;
	public long type_index = -1;
	public long code_block_offset = -1;
	
	public long n5 = -1;

	private void print() {
		String msg = NAME + ": " + function_name + " " + stack_space + " " + type_index + " " + code_block_offset + " " + n5;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomBB6(BinaryReader reader) throws IOException {
		function_name = read_id(reader);

		stack_space = read_int(reader);

		type_index = read_int(reader);

		code_block_offset = read_int(reader);
		
		n5 = read_int(reader);
		
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
			} else {
				break;
			}
			record = MufomRecord.readRecord(reader);
			if (record instanceof MufomASN) {
				asn = (MufomASN) record;
			}
			record = MufomRecord.readRecord(reader);		
		} while ((record instanceof MufomNN) || (record instanceof MufomATN));

		if (record instanceof MufomLN) {
			record.reset(reader);
			MufomBE be = new MufomBE(reader, record_type);
		} else {
			Msg.info(this, "bad 6 be");
			throw new IOException();
		}
		print();
	}
}
