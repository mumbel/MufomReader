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

import org.apache.commons.lang3.ArrayUtils;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DoubleComplexDataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.LongDoubleDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.util.Msg;

/*
 * 11.5 TY (type) Command
 *
 * TY_command       ::= "TY" type_table_entry [ "," parameter ]+ "."
 * type_table_entry ::= hex_number
 * parameter        ::= hex_number | N_variable | "T" type_table_entry
 *
 * {$F2}{nl}{$CE}{n2}[n3][n4]...
 */
public class MufomTY extends MufomRecord {
	public static final String NAME = "TY";
	public static final int record_type = MufomType.MUFOM_CMD_TY;
	public static final int record_subtype = -1;
	public long record_start = -1;
	public long type_index = -1;
	public long variable_index = -1;
	public long ty_code = -1;

	public long builtin = -1;

	MufomUnknownType type_unk = null;
	MufomEnumerationType type_enumumeration = null;
	MufomLargePointerType type_large_pointer = null;
	MufomDataStructureType type_structure = null;
	MufomUnionType type_union = null;
	MufomArrayType type_array = null;
	MufomArrayZType type_arrayz = null;
	MufomBitfieldType type_bitfield = null;
	MufomProcedureType type_procedure = null;
	MufomDeclarationType type_declaration = null;
	MufomSetType type_set = null;
	MufomVoidType type_void = null;
	MufomSimpleEnumType type_simple_enum = null;
	MufomComplexType type_complex = null;
	MufomDoubleComplexType type_double_complex = null;
	MufomRangeType type_range = null;
	MufomSmallPointerType type_small_pointer = null;
	MufomStructBitfieldType type_struct_bitfield = null;
	MufomTypedefType type_typedef = null;
	MufomQualifierType type_qualifier = null;
	MufomFortranArrayType type_fortran = null;
	MufomPascalFileNameType type_pascal_fname = null;
	MufomMType type_m = null;

	private void print() {
		String msg = NAME + ": " + type_index +" " + variable_index + " " + Long.toHexString(ty_code);
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

	public MufomTY(BinaryReader reader, int lex_level, String name) throws IOException {
		record_start = reader.getPointerIndex();
		read_record_type(reader, record_type, record_subtype, NAME);

		if (-1 == lex_level) {
			return;
		} else if (MufomType.MUFOM_DBLK_MTDEF == lex_level) {
			// In BB1 the lex level does not have enough information and is an index, id, and type and ASN
			type_index = read_int(reader);
			int tmp_type = read_char(reader);
			if (MufomType.MUFOM_ID_N != tmp_type) {
				Msg.info(null, "Expected MUFOM_ID_N, " + tmp_type);
				hexdump(reader, record_start, 0x10);
				throw new IOException();
			}
			ty_code = read_int(reader);
		} else if (MufomType.MUFOM_DBLK_GTDEF == lex_level) {
			type_index = read_int(reader);
			if (type_index < 256) {
				Msg.info(this, "invalid type_index " + type_index);
				throw new IOException();
			}

			int tmp_type = read_char(reader);
			if (MufomType.MUFOM_ID_N != tmp_type) {
				Msg.info(null, "Expected MUFOM_ID_N, " + tmp_type);
				hexdump(reader, record_start, 0x10);
				throw new IOException();
			}

			variable_index = read_int(reader);
			if (variable_index < 32) {
				Msg.info(this, "Bad variable_index < 32, " + variable_index);
				hexdump(reader, record_start, 0x20);
				throw new IOException();
			}

			ty_code = read_int(reader);
			switch ((int) ty_code) {
			case MufomType.MUFOM_CT_UNKNOWN:
				type_unk = new MufomUnknownType(reader, name);
				break;
			case MufomType.MUFOM_CT_ARRAY:
				type_array = new MufomArrayType(reader, name);
				break;
			case MufomType.MUFOM_CT_SIMPLE_ENUM:
				type_simple_enum = new MufomSimpleEnumType(reader, name);
				break;
			case MufomType.MUFOM_CT_STRUCT_BITFIELD:
				type_struct_bitfield = new MufomStructBitfieldType(reader, name);
				break;
			case MufomType.MUFOM_CT_ENUMUMERATION:
				type_enumumeration = new MufomEnumerationType(reader, name);
				break;
			case MufomType.MUFOM_CT_SMALL_POINTER:
				type_small_pointer = new MufomSmallPointerType(reader, name);
				break;
			case MufomType.MUFOM_CT_LARGE_POINTER:
				type_large_pointer = new MufomLargePointerType(reader, name);
				break;
			case MufomType.MUFOM_CT_RANGE:
				type_range = new MufomRangeType(reader, name);
				break;
			case MufomType.MUFOM_CT_STRUCTURE:
				type_structure = new MufomDataStructureType(reader, type_index, name);
				break;
			case MufomType.MUFOM_CT_TYPEDEF:
				type_typedef = new MufomTypedefType(reader, type_index, name);
				break;
			case MufomType.MUFOM_CT_UNION:
				type_union = new MufomUnionType(reader, name);
				break;
			case MufomType.MUFOM_CT_VOID:
				type_void = new MufomVoidType(reader, name);
				break;
			case MufomType.MUFOM_CT_DECLARATION:
				type_declaration = new MufomDeclarationType(reader, name);
				break;
			case MufomType.MUFOM_CT_ARRAYZ:
				type_arrayz = new MufomArrayZType(reader, name);
				break;
			case MufomType.MUFOM_CT_FORTRAN_ARRAY:
				type_fortran = new MufomFortranArrayType(reader, name);
				break;
			case MufomType.MUFOM_CT_COMPLEX:
				type_complex = new MufomComplexType(reader, name);
				break;
			case MufomType.MUFOM_CT_DOUBLE_COMPLEX:
				type_double_complex = new MufomDoubleComplexType(reader, name);
				break;
			case MufomType.MUFOM_CT_PASCAL_FNAME:
				type_pascal_fname = new MufomPascalFileNameType(reader, name);
				break;
			case MufomType.MUFOM_CT_BITFIELD:
				type_bitfield = new MufomBitfieldType(reader, name);
				break;
			case MufomType.MUFOM_CT_QUALIFIER:
				type_qualifier = new MufomQualifierType(reader, name);
				break;
			case MufomType.MUFOM_CT_SET:
				type_set = new MufomSetType(reader, name);
				break;
			case MufomType.MUFOM_CT_PROCEDURE:
				type_procedure = new MufomProcedureType(reader, name);
				break;
			case MufomType.MUFOM_CT_M:
				type_m = new MufomMType(reader, name);
				break;
			default:
				Msg.info(this, "Unknown TY " + ty_code);
				throw new IOException();
			}
		} else {
			Msg.info(this, "bad lex-level");
		}
		print();
	}

	public DataType resolveTypeDefIndex(long index, ArrayList<MufomTypedefType> types) {
		for (MufomTypedefType tmp_type : types) {
			if (index == tmp_type.symbol_type_index) {
				return tmp_type.symbol_type;
			}
		}
		return Undefined1DataType.dataType;
	}

	public DataType resolveStructureIndex(long index, ArrayList<MufomTY> types) {
		for (MufomTY tmp_ty : types) {
			if (tmp_ty.type_structure != null) {
				if (index == tmp_ty.type_index) {
					return tmp_ty.type_structure.struct;
				}
			}
		}
		return null;
	}

	public void resolveField(Structure struct, ArrayList<MufomTypedefType> types) {
		DataTypeComponent fields[] = struct.getComponents();
		ArrayUtils.reverse(fields);
		for (DataTypeComponent comp : fields) {
			if (null == comp.getComment()) {
				continue;
			}
			long comp_index = Long.parseLong(comp.getComment());
			DataType new_comp_type = resolveTypeDefIndex(comp_index, types);
			if (comp.getDataType() != new_comp_type) {
				struct.replace(comp.getOrdinal(), new_comp_type, new_comp_type.getLength(), comp.getFieldName(), null);
			}
		}
		return;
	}

	public void resolveStructure(Structure struct, ArrayList<MufomTY> types) {
		DataTypeComponent fields[] = struct.getComponents();
		ArrayUtils.reverse(fields);
		for (DataTypeComponent comp : fields) {
			if (null == comp.getComment()) {
				continue;
			}
			long comp_index = Long.parseLong(comp.getComment());
			DataType new_comp_type = resolveStructureIndex(comp_index, types);
			if (new_comp_type != null && comp.getDataType() != new_comp_type) {
				//TODO
				try {
					struct.replace(comp.getOrdinal(), new_comp_type, new_comp_type.getLength(), comp.getFieldName(), null);
				} catch (IllegalArgumentException e) {
					//
				}
			}
		}
		return;
	}


	/*
	 * Unknown type (sized)  NN/{id}
	 * Mnemonic: ! ($21)     TY/{n3}
	 * size in MAUs          TY/{n4}
	 */
	public class MufomUnknownType {
		public static final int record_type = MufomType.MUFOM_CT_UNKNOWN;

		public MufomUnknownType(BinaryReader reader, String name) throws IOException {
			//TODO n3/n4
			Msg.info(this, "TODO " + record_type);
			hexdump(reader, reader.getPointerIndex(), 0x10);
		}
	}

	/*
	 * Generalized C language enumeration    NN/{id}
	 * Mnemonic: N ($4E)                     TY/{n3}
	 * 0                                     TY/{n4}
	 * size of enumeration in MAUs           TY/{n5}
	 * 1st enum constant name                TY/{n6}
	 * 1st enum constant value               TY/{n7}
	 * additional names/values               [...]
	 */
	public class MufomEnumerationType {
		public static final int record_type = MufomType.MUFOM_CT_ENUMUMERATION;
		public long size = -1;
		public String name = null;
		public long value = -1;

		public MufomEnumerationType(BinaryReader reader, String name) throws IOException {
			//TODO n3/n4/n5/n6/n7  [...]

			long tmp = read_int(reader);
			if (0 != tmp) {
				Msg.info(this, "bad enumeration " + tmp);
				throw new IOException();
			}

			size = read_int(reader);
			while (true) {
				name = read_opt_id(reader);
				if (null == name) {
					break;
				}
				value = read_int(reader);
			}
		}
	}

	/*
	 * 32-bit pointer to another type      NN/{id}
	 * Mnemonic: P ($50)                   TY/{n3}
	 * type index of pointer target        TY/{n4}
	 *
	 */
	public class MufomLargePointerType {
		public static final int record_type = MufomType.MUFOM_CT_LARGE_POINTER;
		public long type_index = -1;

		public MufomLargePointerType(BinaryReader reader, String name) throws IOException {
			//TODO n3/n4

			type_index = read_int(reader);
		}
	}

	/*
	 * data structure            NN/{id}
	 * Mnemonic: S ($53)         TY/{n3}
	 * size of structure         TY/{n4}
	 * member 1 name             TY/{n5}
	 * member 1 type index       TY/{n6}
	 * member 1 MAU offset       TY/{n7}
	 * member 2 name             TY/{n8}
	 * member 2 type index       TY/{n9}
	 * member 2 MAU offset       TY/{n10}
	 * [additional members]      [...]
	 */
	public class MufomDataStructureType {
		public static final int record_type = MufomType.MUFOM_CT_STRUCTURE;
		public long size = -1;
		public String field_name = null;
		public long field_type_index = -1;
		public long field_mau_offset = -1;

		public Structure struct = null;

		public MufomDataStructureType(BinaryReader reader, long index, String name) throws IOException {
			//TODO n3/n4/n5/n6/n7/n8/n9/n10 [...]

			size = read_int(reader);

			if (null == name) {
				name = "mufom_struct_" + index;
			}

			struct = new StructureDataType(new CategoryPath("/MUFOM"), name, (int) size);
			struct.setDescription("" + index);

			while (true) {
				field_name = read_opt_id(reader);
				if (null == field_name) {
					break;
				}
				field_type_index = read_int(reader);
				field_mau_offset = read_int(reader);
				struct.insertAtOffset((int) field_mau_offset, Undefined1DataType.dataType, 1, field_name, "" + field_type_index);
				Msg.trace(this, "STRUCT " + field_name + " " +  field_type_index + " " + field_mau_offset);
			}
		}
	}

	/*
	 * union of members          NN/{id}
	 * Mnemonic: U ($55)         TY/{n3}
	 * size of structure         TY/{n4}
	 * member 1 name             TY/{n5}
	 * member 1 type index       TY/{n6}
	 * member 1 MAU offset       TY/{n7}
	 * member 2 name             TY/{n8}
	 * member 2 type index       TY/{n9}
	 * member 2 MAU offset       TY/{n10}
	 * [additional members]      [...]
	 */
	public class MufomUnionType {
		public static final int record_type = MufomType.MUFOM_CT_UNION;
		public long size = -1;
		public String name = null;
		public long type_index = -1;
		public long mau_offset = -1;

		public MufomUnionType(BinaryReader reader, String name) throws IOException {
			//TODO n3/n4/n5/n6/n7/n8/n9/n10 [...]

			size = read_int(reader);

			while (true) {
				name = read_opt_id(reader);
				if (null == name) {
					break;
				}
				type_index = read_int(reader);
				mau_offset = read_int(reader);
			}
		}
	}

	/*
	 * C array with lower bound = 0       NN/{id}
	 * Mnemonic: Z ($5A) (zero based)     TY/{n3}
	 * type index of component            TY/{n4}
	 * high bound                         TY/{n5}
	 *
	 * When type is unknown, high bound should be -1
	 */
	public class MufomArrayZType {
		public static final int record_type = MufomType.MUFOM_CT_ARRAYZ;
		public long array_type_index = -1;
		public long array_high_bound = -1;

		public MufomArrayZType(BinaryReader reader, String name) throws IOException {
			//TODO n3/n4/n5
			array_type_index = read_int(reader);
			array_high_bound = read_int(reader);
		}
	}

	/*
	 * C array with lower bound = 0       NN/{id}
	 * Mnemonic: A ($41)                  TY/{n3}
	 * type index of component            TY/{n4}
	 * high bound                         TY/{n5}
	 *
	 * When type is unknown, high bound should be -1
	 */
	public class MufomArrayType {
		public static final int record_type = MufomType.MUFOM_CT_ARRAY;

		public MufomArrayType(BinaryReader reader, String name) throws IOException {
			//TODO n3/n4/n5
			Msg.info(this, "TODO " + record_type);
			hexdump(reader, reader.getPointerIndex(), 0x10);
		}
	}

	/* bitfield type                NN/{id}
	 * Mnemonic: G ($67)            TY/{n3}
	 * signed (0=unsign, 1=sign)    TY/{n4}
	 * size (in bits, 1 through n)  TY/{n5}
	 * base type index              TY/{n6}
	 */
	public class MufomBitfieldType {
		public static final int record_type = MufomType.MUFOM_CT_BITFIELD;
		public long signed = -1;
		public long size = -1;
		public long base_type_index = -1;

		public MufomBitfieldType(BinaryReader reader, String name) throws IOException {
			//TODO n3/n4/n5/n6
			signed = read_int(reader);
			size = read_int(reader);
			base_type_index = read_int(reader);
		}
	}

	/*
	 * procedure with compiler dependencies      NN/{id}
	 * Mnemonic: x ($78)                         TY/{n3}
	 * attribute                                 TY/{n4}
	 * frame_type                                TY/{n5}
	 * push_mask                                 TY/{n6}
	 * return_type                               TY/{n7}
	 * # of arguments                            TY/{n8} (-1 if unknown)
	 * [1st argument type]                       TY/{n9}
	 * [2nd argument type]                       TY/{n10}
	 * [additional argument types]               TY/[n11 thru nN]
	 * level                                     TY/{n9 or nN + 1}
	 *
	 */
	public class MufomProcedureType {
		public static final int record_type = MufomType.MUFOM_CT_PROCEDURE;
		public long attribute = -1;
		public long frame_type = -1;
		public long push_mask = -1;
		public long return_type = -1;
		public long number_of_arguments = -1;

		//TODO arguments

		public long level;

		// attribute parameter of the function type is a bit mask of:
		public static final int ATTR_PARAM_UNK       = 1 << 0;
		public static final int ATTR_PARAM_NEAR      = 1 << 1;
		public static final int ATTR_PARAM_FAR       = 1 << 2;
		public static final int ATTR_PARAM_REENTRANT = 1 << 3;
		public static final int ATTR_PARAM_ROMABLE   = 1 << 4;
		public static final int ATTR_PARAM_PASCAL    = 1 << 5;
		public static final int ATTR_PARAM_NOPUSH    = 1 << 6;
		public static final int ATTR_PARAM_INTERRUPT = 1 << 7;

		public MufomProcedureType(BinaryReader reader, String name) throws IOException {
			//TODO n3/n4/n5/n6/n7/n8/n9/n10 [n11..nN] nN+1

			attribute = read_int(reader);
			frame_type = read_int(reader);
			push_mask = read_int(reader);
			return_type = read_int(reader);
			number_of_arguments = read_int(reader);

			for (int i = 0; i < (int) number_of_arguments; i++) {
				long x1 = read_int(reader);
			}

			long unk = read_int(reader);
			level = read_int(reader);
		}
	}

	/*
	 * procedure with compiler dependencies      NN/{id}
	 * Mnemonic: x ($78)                         TY/{n3}
	 * attribute                                 TY/{n4}
	 * frame_type                                TY/{n5}
	 * push_mask                                 TY/{n6}
	 * return_type                               TY/{n7}
	 * # of arguments                            TY/{n8} (-1 if unknown)
	 * [1st argument type]                       TY/{n9}
	 * [2nd argument type]                       TY/{n10}
	 * [additional argument types]               TY/[n11 thru nN]
	 * level                                     TY/{n9 or nN + 1}
	 *
	 */
	public class MufomDeclarationType {
		public static final int record_type = MufomType.MUFOM_CT_DECLARATION;

		// attribute parameter of the function type is a bit mask of:
		public static final int ATTR_PARAM_UNK       = 1 << 0;
		public static final int ATTR_PARAM_NEAR      = 1 << 1;
		public static final int ATTR_PARAM_FAR       = 1 << 2;
		public static final int ATTR_PARAM_REENTRANT = 1 << 3;
		public static final int ATTR_PARAM_ROMABLE   = 1 << 4;
		public static final int ATTR_PARAM_PASCAL    = 1 << 5;
		public static final int ATTR_PARAM_NOPUSH    = 1 << 6;
		public static final int ATTR_PARAM_INTERRUPT = 1 << 7;

		public MufomDeclarationType(BinaryReader reader, String name) throws IOException {
			//TODO n3/n4/n5/n6/n7/n8/n9/n10 [n11..nN] nN+1
		}
	}

	public class MufomSetType {
		public static final int record_type = MufomType.MUFOM_CT_SET;

		public MufomSetType(BinaryReader reader, String name) throws IOException {
			Msg.info(this, "TODO " + record_type);
			hexdump(reader, reader.getPointerIndex(), 0x10);
		}
	}

	public class MufomVoidType {
		public static final int record_type = MufomType.MUFOM_CT_VOID;

		public MufomVoidType(BinaryReader reader, String name) throws IOException {
			Msg.info(this, "TODO " + record_type);
			hexdump(reader, reader.getPointerIndex(), 0x10);
		}
	}

	public class MufomComplexType {
		public static final int record_type = MufomType.MUFOM_CT_COMPLEX;

		public MufomComplexType(BinaryReader reader, String name) throws IOException {
			Msg.info(this, "TODO " + record_type);
			hexdump(reader, reader.getPointerIndex(), 0x10);
		}
	}

	public class MufomDoubleComplexType {
		public static final int record_type = MufomType.MUFOM_CT_DOUBLE_COMPLEX;

		public MufomDoubleComplexType(BinaryReader reader, String name) throws IOException {
			Msg.info(this, "TODO " + record_type);
			hexdump(reader, reader.getPointerIndex(), 0x10);
		}
	}

	public class MufomQualifierType {
		public static final int record_type = MufomType.MUFOM_CT_QUALIFIER;

		public MufomQualifierType(BinaryReader reader, String name) throws IOException {
			Msg.info(this, "TODO " + record_type);
			hexdump(reader, reader.getPointerIndex(), 0x10);
		}
	}

	public class MufomTypedefType {
		public static final int record_type = MufomType.MUFOM_CT_TYPEDEF;
		public long symbol_type_index = -1;
		public DataType symbol_type;

		public MufomTypedefType(BinaryReader reader, long index, String name) throws IOException {

			symbol_type_index = index;
			long tmp_index = read_int(reader);
			switch ((int) tmp_index) {
	        case MufomType.MUFOM_BUILTIN_UNK:
	        	Msg.info(this, "TYPE: UNK");
	        	symbol_type = Undefined1DataType.dataType;
	        	break;
	        case MufomType.MUFOM_BUILTIN_V:
	        	Msg.info(this, "TYPE: V");
	        	symbol_type = VoidDataType.dataType;
	        	break;
	        case MufomType.MUFOM_BUILTIN_B:
	        	Msg.info(this, "TYPE: B");
	        	symbol_type = CharDataType.dataType;
	        	break;
	        case MufomType.MUFOM_BUILTIN_C:
	        	Msg.info(this, "TYPE: C");
	        	symbol_type = UnsignedCharDataType.dataType;
	            break;
	        case MufomType.MUFOM_BUILTIN_H:
	        	Msg.info(this, "TYPE: H");
	        	symbol_type = ShortDataType.dataType;
	            break;
	        case MufomType.MUFOM_BUILTIN_I:
	        	Msg.info(this, "TYPE: I");
	        	symbol_type = UnsignedShortDataType.dataType;
	            break;
	        case MufomType.MUFOM_BUILTIN_L:
	        	Msg.info(this, "TYPE: L");
	        	symbol_type = LongDataType.dataType;
	            break;
	        case MufomType.MUFOM_BUILTIN_M:
	        	Msg.info(this, "TYPE: M");
	        	symbol_type = UnsignedLongDataType.dataType;
	            break;
	        case MufomType.MUFOM_BUILTIN_N:
	        	Msg.info(this, "TYPE: N");
	        	symbol_type = LongLongDataType.dataType;
	            break;
	        case MufomType.MUFOM_BUILTIN_Q:
	        	Msg.info(this, "TYPE: Q");
	        	symbol_type = UnsignedLongLongDataType.dataType;
	            break;
	        case MufomType.MUFOM_BUILTIN_F:
	        	Msg.info(this, "TYPE: F");
	        	symbol_type = FloatDataType.dataType;
	            break;
	        case MufomType.MUFOM_BUILTIN_D:
	        	Msg.info(this, "TYPE: D");
	        	symbol_type = DoubleDataType.dataType;
	            break;
	        case MufomType.MUFOM_BUILTIN_K:
	        	Msg.info(this, "TYPE: K");
	        	symbol_type = DoubleComplexDataType.dataType;
	            break;
	        case MufomType.MUFOM_BUILTIN_G:
	        	Msg.info(this, "TYPE: G");
	        	symbol_type = LongDoubleDataType.dataType;
	            break;
	        case MufomType.MUFOM_BUILTIN_S:
	        	Msg.info(this, "TYPE: S");
	        	symbol_type = StringDataType.dataType;
	            break;
	        case MufomType.MUFOM_BUILTIN_J:
	        	Msg.info(this, "TYPE: J");
	        	symbol_type = PointerDataType.dataType;
	            break;
	        case MufomType.MUFOM_BUILTIN_PUNK:
	        	Msg.info(this, "TYPE: PUNK");
	        	symbol_type = PointerDataType.dataType.newPointer(Undefined1DataType.dataType);
	            break;
	        case MufomType.MUFOM_BUILTIN_PV:
	        	Msg.info(this, "TYPE: PV");
	        	symbol_type = PointerDataType.dataType.newPointer(VoidDataType.dataType);
	            break;
	        case MufomType.MUFOM_BUILTIN_PB:
	        	Msg.info(this, "TYPE: PB");
	        	symbol_type = PointerDataType.dataType.newPointer(CharDataType.dataType);
	        	break;
	        case MufomType.MUFOM_BUILTIN_PC:
	        	Msg.info(this, "TYPE: PC");
	        	symbol_type = PointerDataType.dataType.newPointer(UnsignedCharDataType.dataType);
	        	break;
	        case MufomType.MUFOM_BUILTIN_PH:
	        	Msg.info(this, "TYPE: PH");
	        	symbol_type = PointerDataType.dataType.newPointer(ShortDataType.dataType);
	        	break;
	        case MufomType.MUFOM_BUILTIN_PI:
	        	Msg.info(this, "TYPE: PI");
	        	symbol_type = PointerDataType.dataType.newPointer(UnsignedShortDataType.dataType);
	        	break;
	        case MufomType.MUFOM_BUILTIN_PL:
	        	Msg.info(this, "TYPE: PL");
	        	symbol_type = PointerDataType.dataType.newPointer(LongDataType.dataType);
	            break;
	        case MufomType.MUFOM_BUILTIN_PM:
	        	Msg.info(this, "TYPE: PM");
	        	symbol_type = PointerDataType.dataType.newPointer(UnsignedLongDataType.dataType);
	            break;
	        case MufomType.MUFOM_BUILTIN_PN:
	        	Msg.info(this, "TYPE: PN");
	        	symbol_type = PointerDataType.dataType.newPointer(LongLongDataType.dataType);
	            break;
	        case MufomType.MUFOM_BUILTIN_PQ:
	        	Msg.info(this, "TYPE: PQ");
	        	symbol_type = PointerDataType.dataType.newPointer(UnsignedLongLongDataType.dataType);
	            break;
	        case MufomType.MUFOM_BUILTIN_PF:
	        	Msg.info(this, "TYPE: PF");
	        	symbol_type = PointerDataType.dataType.newPointer(FloatDataType.dataType);
	            break;
	        case MufomType.MUFOM_BUILTIN_PD:
	        	Msg.info(this, "TYPE: PD");
	        	symbol_type = PointerDataType.dataType.newPointer(DoubleDataType.dataType);
	            break;
	        case MufomType.MUFOM_BUILTIN_PK:
	        	Msg.info(this, "TYPE: PK");
	        	symbol_type = PointerDataType.dataType.newPointer(DoubleComplexDataType.dataType);
	        	break;
	        case MufomType.MUFOM_BUILTIN_PG:
	        	Msg.info(this, "TYPE: PG");
	        	symbol_type = PointerDataType.dataType.newPointer(LongDoubleDataType.dataType);
	            break;
	        case MufomType.MUFOM_BUILTIN_PS:
	        	Msg.info(this, "TYPE: PS");
	        	symbol_type = PointerDataType.dataType.newPointer(StringDataType.dataType);
	            break;
	        default:
	        	Msg.info(this, "Bad type " + symbol_type_index + " " + tmp_index);
	        	throw new IOException();
	        }
		}
	}

	public class MufomRangeType {
		public static final int record_type = MufomType.MUFOM_CT_RANGE;

		public MufomRangeType(BinaryReader reader, String name) throws IOException {
			Msg.info(this, "TODO " + record_type);
			hexdump(reader, reader.getPointerIndex(), 0x10);
		}
	}

	public class MufomSimpleEnumType {
		public static final int record_type = MufomType.MUFOM_CT_SIMPLE_ENUM;

		public MufomSimpleEnumType(BinaryReader reader, String name) throws IOException {
			Msg.info(this, "TODO " + record_type);
			hexdump(reader, reader.getPointerIndex(), 0x10);
		}
	}

	public class MufomSmallPointerType {
		public static final int record_type = MufomType.MUFOM_CT_SMALL_POINTER;

		public MufomSmallPointerType(BinaryReader reader, String name) throws IOException {
			Msg.info(this, "TODO " + record_type);
			hexdump(reader, reader.getPointerIndex(), 0x10);
		}
	}

	public class MufomStructBitfieldType {
		public static final int record_type = MufomType.MUFOM_CT_STRUCT_BITFIELD;

		public MufomStructBitfieldType(BinaryReader reader, String name) throws IOException {
			Msg.info(this, "TODO " + record_type);
			hexdump(reader, reader.getPointerIndex(), 0x10);
		}
	}

	public class MufomFortranArrayType {
		public static final int record_type = MufomType.MUFOM_CT_FORTRAN_ARRAY;

		public MufomFortranArrayType(BinaryReader reader, String name) throws IOException {
			Msg.info(this, "TODO " + record_type);
			hexdump(reader, reader.getPointerIndex(), 0x10);
		}
	}

	public class MufomPascalFileNameType {
		public static final int record_type = MufomType.MUFOM_CT_PASCAL_FNAME;

		public MufomPascalFileNameType(BinaryReader reader, String name) throws IOException {
			Msg.info(this, "TODO " + record_type);
			hexdump(reader, reader.getPointerIndex(), 0x10);
		}
	}

	public class MufomMType {
		public static final int record_type = MufomType.MUFOM_CT_M;

		public MufomMType(BinaryReader reader, String name) throws IOException {
			String id1 = read_id(reader);
			String id2 = read_id(reader);
			String id3 = read_id(reader);
			String id4 = read_id(reader);
			long n1 = read_int(reader);
		}
	}
}
