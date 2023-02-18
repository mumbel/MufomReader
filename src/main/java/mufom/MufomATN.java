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
 * Attribute Records (ATN)
 *
 * AT-command → “AT” variable “,” type-table-entry (“,” lex-level (“,” hexnumber)* )? “.”
 * variable → I-variable | N-variable | X-variable
 * type-table-entry → hexnumber
 * lex-level → hexnumber
 *
 * N-variable → “N” hexnumber
 *
 * {$F1}{$CE}{n1}{n2}{n3}[x1][x2][Id]
 */
public class MufomATN extends MufomRecord {
	public static final String NAME = "ATN";
	public static final int record_type = MufomType.MUFOM_CMD_AT;
	public static final int record_subtype = MufomType.MUFOM_ID_N;
	public long record_start = -1;
	public long symbol_name_index = -1;
	public long lex_level = -1;
	public long attribute_definition = -1;
    public String id = null;
    public long x1 = -1;
    public long x2 = -1;
    public long x3 = -1;
    public long x4 = -1;
    public long x5 = -1;
    public long x6 = -1;
    
    MufomProcedureMisc pmisc = null;
    MufomVariableMisc vmisc = null;
    MufomModuleMisc mmisc = null;

    private void print() {
		String msg = NAME + ": idx: " + symbol_name_index + " attr_def: " + attribute_definition;
		if (do_debug) {
			Msg.info(this, msg);
		} else {
			Msg.trace(this, msg);
		}
	}

    public MufomATN(BinaryReader reader) throws IOException {
    	record_start = reader.getPointerIndex();
    	read_record_type(reader, record_type, record_subtype, NAME);
 
		symbol_name_index = read_int(reader);

		lex_level = read_int(reader);
//		if (0 != lex_level) {
//			Msg.info(this, "Bad lex-level " + lex_level);
//			throw new IOException();
//		}

		attribute_definition = read_int(reader);
        switch ((int) attribute_definition) {
        case MufomType.MUFOM_AD_AUTOMATIC:
        	x1 = read_int(reader);
            break;
        case MufomType.MUFOM_AD_REGISTER:
        	x1 = read_int(reader);
            break;
        case MufomType.MUFOM_AD_STATIC:
        	// ASN
            break;
        case MufomType.MUFOM_AD_EXTFUNC:
            break;
        case MufomType.MUFOM_AD_EXTVAR:
            break;
        case MufomType.MUFOM_AD_LINENUMBER:
            x1 = read_int(reader);
            x2 = read_int(reader);
            x3 = read_opt_int(reader);
            x4 = read_opt_int(reader);
            // ASN
            break;
        case MufomType.MUFOM_AD_GLOBAL:
        	// ASN
            break;
        case MufomType.MUFOM_AD_LIFETIME:
            x1 = read_int(reader);
            break;
        case MufomType.MUFOM_AD_LOCKEDREGISTER:
            x1 = read_int(reader);
            x2 = read_opt_int(reader);
            break;
        case MufomType.MUFOM_AD_FORTRAN:
            throw new IOException();
        case MufomType.MUFOM_AD_BASED:
            x1 = read_int(reader); // offset value
            x2 = read_int(reader); // control number
            x3 = read_opt_int(reader); // public/local indicator
            x4 = read_opt_int(reader); // memory space indicator
            x5 = read_opt_int(reader); // number of MAUs for base value
            break;
        case MufomType.MUFOM_AD_CONSTANT:
            x1 = read_int(reader);
            x2 = read_opt_int(reader);
            x3 = read_opt_int(reader);
            id = read_opt_id(reader);
            break;
        case MufomType.MUFOM_AD_STATICSYMBOL:
            x1 = read_int(reader);
            x2 = read_opt_int(reader);
            // ASN
            break;
        case MufomType.MUFOM_AD_TYPE:
        	// set object type relocatable to x
            x1 = read_int(reader);
            break;
        case MufomType.MUFOM_AD_CASE:
            x1 = read_int(reader);
            break;
        case MufomType.MUFOM_AD_STATUS:
            x1 = read_int(reader);
            break;
        case MufomType.ieee_unknown_56_enum:
            x1 = read_int(reader);
            break;
        case MufomType.MUFOM_AD_ENV:
            x1 = read_int(reader);
            break;
        case MufomType.MUFOM_AD_VERSION:
            x1 = read_int(reader);
            x2 = read_int(reader);
            break;
        case MufomType.MUFOM_AD_TOOLVERSION:
            x1 = read_int(reader);     // tool
            x2 = read_int(reader);     // version
            x3 = read_int(reader);     // revision
            x4 = read_opt_int(reader); // level
            break;
        case MufomType.MUFOM_AD_DATETIME:
            x1 = read_int(reader); // year
            x2 = read_int(reader); // mon
            x3 = read_int(reader); // day
            x4 = read_int(reader); // hour
            x5 = read_int(reader); // min
            x6 = read_int(reader); // sec
            break;
        case MufomType.MUFOM_AD_PROCEDURE_MISC:
        	pmisc = new MufomProcedureMisc(reader);
        	break;
        case MufomType.MUFOM_AD_VARIABLE_MISC:
        	vmisc = new MufomVariableMisc(reader);
        	break;
        case MufomType.MUFOM_AD_MODULE_MISC:
        	mmisc = new MufomModuleMisc(reader);
        	break;
        case MufomType.MUFOM_AD_MSTRING:
        	id = read_id(reader);
        	break;
         default:
            Msg.info(null, "Bad ATN " + symbol_name_index + " " + attribute_definition);
            hexdump(reader, reader.getPointerIndex(), 0x10);
            throw new IOException();
         }
        //print();
    }
    
    /*
     * 
     */
    public class MufomProcedureMisc {
    	public static final String NAME = "PMISC";
    	public static final int record_type = MufomType.MUFOM_AD_PROCEDURE_MISC;
    	public static final int record_subtype = -1;
    	public long record_start = -1;
		public long information_code = -1;
		public long number_of_records = -1;
		public MufomRecord[] cluster = null;

    	public MufomProcedureMisc(BinaryReader reader) throws IOException {
    		record_start = reader.getPointerIndex();
        	
        	information_code = read_int(reader);

        	number_of_records = read_int(reader);

        	cluster = new MufomRecord[(int) number_of_records];
        	for (long i = 0; i < number_of_records; i++) {
        		MufomRecord record = MufomRecord.readRecord(reader);
        		if (record instanceof MufomATN || record instanceof MufomASN) {
        			cluster[(int) i] = record;
        		} else {
        			Msg.info(this, "Bad pmisc record");
        			throw new IOException();
        		}
        	}
    	}
    }

    /*
     * 
     */
    public class MufomVariableMisc {
    	public static final String NAME = "VMISC";
    	public static final int record_type = MufomType.MUFOM_AD_VARIABLE_MISC;
    	public static final int record_subtype = -1;
    	public long record_start = -1;
		public long information_code = -1;
		public long number_of_records = -1;
		public MufomRecord[] cluster = null;

    	public MufomVariableMisc(BinaryReader reader) throws IOException {
    		record_start = reader.getPointerIndex();
    		
        	information_code = read_int(reader);

        	number_of_records = read_int(reader);

        	cluster = new MufomRecord[(int) number_of_records];
        	for (long i = 0; i < number_of_records; i++) {
        		MufomRecord record = MufomRecord.readRecord(reader);
        		if (record instanceof MufomATN || record instanceof MufomASN) {
        			cluster[(int) i] = record;
        		} else {
        			Msg.info(this, "Bad vmisc record");
        			throw new IOException();
        		}
        	}
    	}
    }
    
    /*
     * 
     */
    public class MufomModuleMisc {
    	public static final String NAME = "MMISC";
    	public static final int record_type = MufomType.MUFOM_AD_MODULE_MISC;
    	public static final int record_subtype = -1;
    	public long record_start = -1;
		public long information_code = -1;
		public long number_of_records = -1;
		public MufomRecord[] cluster = null;

    	public MufomModuleMisc(BinaryReader reader) throws IOException {
    		record_start = reader.getPointerIndex();

        	information_code = read_int(reader);

        	number_of_records = read_int(reader);

        	cluster = new MufomRecord[(int) number_of_records];
        	for (long i = 0; i < number_of_records; i++) {
        		MufomRecord record = MufomRecord.readRecord(reader);
        		if (record instanceof MufomATN || record instanceof MufomASN) {
        			cluster[(int) i] = record;
        		} else {
        			Msg.info(this, "Bad mmisc record");
        			throw new IOException();
        		}
        	}
    	}
    }
}
