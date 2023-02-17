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
 * Block End (BE)
 *
 * {$F9}[{n1}]
 */
public class MufomBE extends MufomRecord {
	public static final String NAME = "BE";
	public static final int record_type = MufomType.MUFOM_CMD_LN;
	public static final int record_subtype = -1;
	public long record_start = -1;
	public int begin_block = -1;
	
	public long ending_address = -1;
	public long module_section_length = -1;

	private void print() {
		String msg = NAME + ": " + begin_block;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomBE(BinaryReader reader, int bb) throws IOException {
		Msg.info(this, String.format("%08x ENTER %s", reader.getPointerIndex(), NAME));
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);
		begin_block = bb;

		switch (begin_block) {
		case MufomType.MUFOM_DBLK_GFUNC:
		case MufomType.MUFOM_DBLK_LFUNC:
			//TODO Expression defining the ending address of the function (in minimum address units)
			ending_address = read_int(reader);
			break;
		case MufomType.MUFOM_DBLK_MODSEC:
			//TODO Expression defining the size in minimum address units of the module section
			module_section_length = read_int(reader);
			break;
		default:
			break;
		}
		print();

		Msg.info(this, String.format("%08x EXIT %s", reader.getPointerIndex(), NAME));
	}
}
