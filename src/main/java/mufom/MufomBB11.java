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
 * The module portion of a section.
 * 
 * {$F8}{$0B}{0}{Id}{n2}{n3}{n4}[n5]
 */
public class MufomBB11 extends MufomRecord {
	public static final int record_type = MufomType.MUFOM_DBLK_MODSEC;
	public static final String NAME = "BB11";
	public long record_offset = -1;
	public String section_name = null;
	public long section_type = -1;
	public long section_number = -1;
	public long section_offset = -1;
	public long n5 = -1;
	
	MufomNN nn = null;
	MufomATN atn = null;
	MufomASN asn = null;

	private void print() {
		String msg = "BB11: " + section_name + " " + section_type + " " + section_number + " 0x" +
				Long.toHexString(section_offset) + " " + n5;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomBB11(BinaryReader reader) throws IOException {
		Msg.info(this, String.format("%08x ENTER %s", reader.getPointerIndex(), NAME));

		record_offset = reader.getPointerIndex();
		
		section_name = read_id(reader);

		section_type = read_int(reader);

		section_number = read_int(reader);

		section_offset = read_int(reader);
		
		n5 = read_opt_int(reader);

		// Expression start/end?
		
		int tmp = read_char(reader);
		if (MufomType.MUFOM_USER_90 == tmp) {
			read_int(reader);
		} else {
			reader.setPointerIndex(reader.getPointerIndex() - 1);
		}

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
		} while (record instanceof MufomNN);

		if (record instanceof MufomBB) {
			MufomBB bb = (MufomBB) record;
			
			if (MufomType.MUFOM_DBLK_ASMSC == bb.begin_block) {
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
		} while (record instanceof MufomNN);
		
		if (record instanceof MufomLN) {
			record.reset(reader);
			MufomBE be11 = new MufomBE(reader, record_type);
		} else {
			Msg.info(this, "bad be 11 " + record);
			throw new IOException();
		}
		print();
	}
}
