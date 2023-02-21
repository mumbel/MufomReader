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
 * Global type definitions.
 *
 * {NN {TY}}
 */
public class MufomBB2 extends MufomRecord {
	public static final int record_type = MufomType.MUFOM_DBLK_GTDEF;
	public static final String NAME = "BB2";
	public String module_name = null;

	public ArrayList<MufomTY> types = new ArrayList<MufomTY>();
	public ArrayList<MufomTY> typedefs = new ArrayList<MufomTY>();
	public ArrayList<MufomTY> enumerations = new ArrayList<MufomTY>();
	public ArrayList<MufomTY> unions = new ArrayList<MufomTY>();

	private void print() {
		String msg = "BB2: '" + module_name + "'";
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomBB2(BinaryReader reader) throws IOException {
		this(reader, null);
	}

	public MufomBB2(BinaryReader reader, DataTypeManager dtm) throws IOException {
		Msg.trace(this, String.format("%08x ", reader.getPointerIndex()) + "ENTER MufomBB2");

		//TODO  Module-Scope Type Definitions (BB2)
		//TODO      NN and TY records
		//TODO  Module-Scope Type Definitions End (BE2)

		module_name = read_id(reader);

		MufomNN nn = null;
		MufomTY ty = null;
		MufomRecord record = MufomRecord.readRecord(reader);

		do {
			if (record instanceof MufomNN) {
				nn = (MufomNN) record;
				record = MufomRecord.readRecord(reader);
			}

			while (record instanceof MufomTY) {
				record.reset(reader);
				ty = new MufomTY(reader, record_type, nn.symbol_name, dtm);
				if (ty.type_typedef != null) {
					typedefs.add(ty);
				}
				if (ty.type_structure != null) {
					types.add(ty);
				}
				if (ty.type_enumumeration != null) {
					enumerations.add(ty);
				}
				if (ty.type_union != null) {
					unions.add(ty);
				}
				record = MufomRecord.readRecord(reader);
			}
		} while (record instanceof MufomNN);

		if (record instanceof MufomLN) {
			record.reset(reader);
			MufomBE be = new MufomBE(reader, record_type);
		} else {
			Msg.info(this, "bad bb 2");
			throw new IOException();
		}
		print();
	}
}
