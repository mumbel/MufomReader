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

/*
 * 0nnnnnnn CCC...C    - character string, to 127 bytes
 * 0xxxxxxx            - small number, 0 to 127
 * 0nnnnnnn BBB...B    - load constant, to 127 bytes
 * 0nnnnnnn CCC...C    - identifier, to 127 bytes
 * 10000000            - omitted
 * 1000nnnn BBB...B    - hex number, 0 to 8 bytes
 * 1001xxxx            - implementer-defined functions
 * 101xxxxx            - standard functions
 * 110xxxxx (0nnnnnnn) - standard variables and identifiers
 * 111xxxxx            - standard command names
 * xxxxxxxx            - checksum ( % 256)
 */
public abstract class MufomType {

	/* 0x00 - 0x7f - regular string or one byte number */

	/* 0x80 - omitted optional number field */
	public static final int MUFOM_OMITTED = 0x80;

	/* 0x81 - 0x88 - numbers outside range of 0-127 */

	/* 0x89 - 0x8f - unused  */

	/* 0x90 - 0xa0 - user defined function codes */
	
	/* User defined */
	public static final int MUFOM_USER_90 = 0x90;
	
	/* User defined */
	public static final int MUFOM_USER_91 = 0x91;
	
	/* User defined */
	public static final int MUFOM_USER_92 = 0x92;
	
	/* User defined */
	public static final int MUFOM_USER_93 = 0x93;
	
	/* User defined */
	public static final int MUFOM_USER_94 = 0x94;
	
	/* User defined */
	public static final int MUFOM_USER_95 = 0x95;
	
	/* User defined */
	public static final int MUFOM_USER_96 = 0x96;
	
	/* User defined */
	public static final int MUFOM_USER_97 = 0x97;
	
	/* User defined */
	public static final int MUFOM_USER_98 = 0x98;
	
	/* User defined */
	public static final int MUFOM_USER_99 = 0x99;
	
	/* User defined */
	public static final int MUFOM_USER_9A = 0x9a;
	
	/* User defined */
	public static final int MUFOM_USER_9B = 0x9b;
	
	/* User defined */
	public static final int MUFOM_USER_9C = 0x9c;
	
	/* User defined */
	public static final int MUFOM_USER_9D = 0x9d;
	
	/* User defined */
	public static final int MUFOM_USER_9E = 0x9e;
	
	/* User defined */
	public static final int MUFOM_USER_9F = 0x9f;	

	/* 0xdb - 0xdd - unused */

	/* 0xfa - 0xff - unused */

	/* Function @F */
	public static final int MUFOM_FUNC_F = 0xa0;

	/* Function @T */
	public static final int MUFOM_FUNC_T = 0xa1;

	/* Function @ABS */
	public static final int MUFOM_FUNC_ABS = 0xa2;

	/* Function @NEG */
	public static final int MUFOM_FUNC_NEG = 0xa3;

	/* Function @NOT */
	public static final int MUFOM_FUNC_NOT = 0xa4;

	/* Function + */
	public static final int MUFOM_FUNC_ADD = 0xa5;

	/* Function - */
	public static final int MUFOM_FUNC_SUB = 0xa6;

	/* Function / */
	public static final int MUFOM_FUNC_DIV = 0xa7;

	/* Function * */
	public static final int MUFOM_FUNC_MUL = 0xa8;

	/* Function @MAX */
	public static final int MUFOM_FUNC_MAX = 0xa9;

	/* Function @MIN */
	public static final int MUFOM_FUNC_MIN = 0xaa;

	/* Function @MOD */
	public static final int MUFOM_FUNC_MOD = 0xab;

	/* Function < */
	public static final int MUFOM_FUNC_LT = 0xac;

	/* Function > */
	public static final int MUFOM_FUNC_GT = 0xad;

	/* Function = */
	public static final int MUFOM_FUNC_EQ = 0xae;

	/* Function != */
	public static final int MUFOM_FUNC_NEQ = 0xaf;

	/* Function @AND */
	public static final int MUFOM_FUNC_AND = 0xb0;

	/* Function @OR */
	public static final int MUFOM_FUNC_OR = 0xb1;

	/* Function @XOR */
	public static final int MUFOM_FUNC_XOR = 0xb2;

	/* Function @EXT */
	public static final int MUFOM_FUNC_EXT = 0xb3;

	/* Function @INS */
	public static final int MUFOM_FUNC_INS = 0xb4;

	/* Function @ERR */
	public static final int MUFOM_FUNC_ERR = 0xb5;

	/* Function @IF */
	public static final int MUFOM_FUNC_IF = 0xb6;

	/* Function @ELSE */
	public static final int MUFOM_FUNC_ELSE = 0xb7;

	/* Function @END */
	public static final int MUFOM_FUNC_END = 0xb8;

	/* Function @ISDEF */
	public static final int MUFOM_FUNC_ISDEF = 0xb9;
	
	/* Function signed ( */
	public static final int MUFOM_FUNC_SOPEN = 0xba;
	
	/* Function signed ) */
	public static final int MUFOM_FUNC_SCLOSE = 0xbb;
	
	/* Function unsigned ( */
	public static final int MUFOM_FUNC_UOPEN = 0xbc;
	
	/* Function unsigned ) */
	public static final int MUFOM_FUNC_UCLOSE = 0xbd;

	/* Function ( */
	public static final int MUFOM_FUNC_OPEN = 0xbe;
	
	/* Function )*/
	public static final int MUFOM_FUNC_CLOSE = 0xbf;

	/* Identifier NULL */
	public static final int MUFOM_ID_NULL = 0xc0;

	/* Identifier A */
	public static final int MUFOM_ID_A = 0xc1;

	/* Identifier B */
	public static final int MUFOM_ID_B = 0xc2;

	/* Identifier C */
	public static final int MUFOM_ID_C = 0xc3;

	/* Identifier D */
	public static final int MUFOM_ID_D = 0xc4;

	/* Identifier E */
	public static final int MUFOM_ID_E = 0xc5;

	/* Identifier F */
	public static final int MUFOM_ID_F = 0xc6;

	/*
	 * Identifier G
	 * Execution starting address
	 */
	public static final int MUFOM_ID_G = 0xc7;

	/* Identifier H */
	public static final int MUFOM_ID_H = 0xc8;

	/*
	 * Identifier I
	 * Address of public symbol
	 */
	public static final int MUFOM_ID_I = 0xc9;

	/* Identifier J */
	public static final int MUFOM_ID_J = 0xca;

	/* Identifier K */
	public static final int MUFOM_ID_K = 0xcb;

	/* Identifier L */
	public static final int MUFOM_ID_L = 0xcc;

	/* Identifier M */
	public static final int MUFOM_ID_M = 0xcd;

	/*
	 * Identifier N
	 * Address of local symbol
	 */
	public static final int MUFOM_ID_N = 0xce;

	/* Identifier O */
	public static final int MUFOM_ID_O = 0xcf;

	/*
	 * Identifier P
	 * The program counter for section
	 * Implicitly changes with each LR, LD, or LT
	 */
	public static final int MUFOM_ID_P = 0xd0;

	/* Identifier Q */
	public static final int MUFOM_ID_Q = 0xd1;

	/* Identifier R */
	public static final int MUFOM_ID_R = 0xd2;

	/*
	 * Identifier S
	 * The size in minimum address units
	 */
	public static final int MUFOM_ID_S = 0xd3;

	/* Identifier T */
	public static final int MUFOM_ID_T = 0xd4;

	/* Identifier U */
	public static final int MUFOM_ID_U = 0xd5;

	/* Identifier V */
	public static final int MUFOM_ID_V = 0xd6;
	
	/*
	 * Identifier W
	 * The file offset in bytes of the part of the object file from the
	 * beginning of the file
	 */
	public static final int MUFOM_ID_W = 0xd7;

	/* Identifier X */
	public static final int MUFOM_ID_X = 0xd8;

	/* Identifier Y */
	public static final int MUFOM_ID_Y = 0xd9;

	/* Identifier Z */
	public static final int MUFOM_ID_Z = 0xda;

	/* Extension length 1-byte */
	public static final int MUFOM_EXTB = 0xde;

	/* Extension length 2-byte */
	public static final int MUFOM_EXTH = 0xdf;

	/* Command MB - Module begin */
	public static final int MUFOM_CMD_MB = 0xe0;

	/* Command ME - Module end */
	public static final int MUFOM_CMD_ME = 0xe1;

	/* Command AS - Assign */
	public static final int MUFOM_CMD_AS = 0xe2;

	/* Command IR - Initialize relocation base */
	public static final int MUFOM_CMD_IR = 0xe3;

	/* Command LR - Load with relocation */
	public static final int MUFOM_CMD_LR = 0xe4;

	/* Command SB - Section begin */
	public static final int MUFOM_CMD_SB = 0xe5;

	/* Command ST - Section type */
	public static final int MUFOM_CMD_ST = 0xe6;

	/* Command SA - Section alignment */
	public static final int MUFOM_CMD_SA = 0xe7;

	/* Command NI - Internal name */
	public static final int MUFOM_CMD_NI = 0xe8;

	/* Command NX - External name */
	public static final int MUFOM_CMD_NX = 0xe9;

	/* Command CO - Comment */
	public static final int MUFOM_CMD_CO = 0xea;

	/* Command DT - Date and time */
	public static final int MUFOM_CMD_DT = 0xeb;

	/* Command AD - Address description */
	public static final int MUFOM_CMD_AD = 0xec;

	/* Command LD - Load */
	public static final int MUFOM_CMD_LD = 0xed;

	/* Command CS (with sum) - Checksum followed by sum value */
	public static final int MUFOM_CMD_CSS = 0xee;

	/* Command CS - Checksum (reset sum to 0) */
	public static final int MUFOM_CMD_CS = 0xef;

	/* Command NN - Name */
	public static final int MUFOM_CMD_NN = 0xf0;

	/* Command AT - Attribute */
	public static final int MUFOM_CMD_AT = 0xf1;

	/* Command TY - Type */
	public static final int MUFOM_CMD_TY = 0xf2;

	/* Command RI - Retain internal symbol */
	public static final int MUFOM_CMD_RI = 0xf3;

	/* Command WX - Weak external */
	public static final int MUFOM_CMD_WX = 0xf4;

	/* Command LI - Library search list*/
	public static final int MUFOM_CMD_LI = 0xf5;

	/* Command LX - Library external */
	public static final int MUFOM_CMD_LX = 0xf6;

	/* Command RE - Replicate */
	public static final int MUFOM_CMD_RE = 0xf7;

	/* Command SC - Scope definition */
	public static final int MUFOM_CMD_SC = 0xf8;

	/* Command LN - Line number */
	public static final int MUFOM_CMD_LN = 0xf9;

	/* Attribute Definition - Automatic variable
	 * [x1]
	 */
	public static final int MUFOM_AD_AUTOMATIC = 0x01;
	
	/* Attribute Definition - Register variable
	 * [x1]
	 */
	public static final int MUFOM_AD_REGISTER = 0x02;

	/* Attribute Definition - Static variable
	 * ASN or ASI
	 */
	public static final int MUFOM_AD_STATIC = 0x03;
	
	/* Attribute Definition - External function
	 */
	public static final int MUFOM_AD_EXTFUNC = 0x04;
	
	/* Attribute Definition - External variable
	 */
	public static final int MUFOM_AD_EXTVAR = 0x05;
	
	/*
	 * Attribute Definition - Line number
	 * [x1], [x2], opt [x3], opt[x4] - line number and column
	 * ASN
	 */
	public static final int MUFOM_AD_LINENUMBER = 0x07;
	
	/*
	 * Attribute Definition - Global variable
	 * ASN
	 */
	public static final int MUFOM_AD_GLOBAL = 0x08;
	
	/*
	 * Attribute Definition - Variable lifetime information
	 * [x1]
	 */
	public static final int MUFOM_AD_LIFETIME = 0x09;
	
	/*
	 * Attribute Definition - Variable name as locked register
	 * [x1] index of register name
	 */
	public static final int MUFOM_AD_LOCKEDREGISTER = 0x0a;
	
	/*
	 * Attribute Definition - FORTRAN common
	 */
	public static final int MUFOM_AD_FORTRAN = 0x0b;
	
	/*
	 * Attribute Definition - Based variable
	 * [x1] [x2] [x3] [x4] [x5]
	 */
	public static final int MUFOM_AD_BASED = 0x0c;
	
	/*
	 * Attribute Definition - Constant
	 * [x1] [x2] [x3] [id]
	 * ASN
	 */
	public static final int MUFOM_AD_CONSTANT = 0x10;

	/*
	 * Attribute Definition - Static symbol
	 * [x1] and [x2] - number of elements, local or global=1
	 * ASN
	 */
	public static final int MUFOM_AD_STATICSYMBOL = 0x13;
	
	/*
	 * Attribute Definition - version number
	 * TODO  HPATN_SFVNO
	 */
	public static final int MUFOM_AD_SFVERSION = 0x24;

	/*
	 * Attribute Definition - Object format version number
	 * [x1] and [x2] defining version number and revision
	 */
	public static final int MUFOM_AD_VERSION = 0x25;

	/*
	 * Attribute Definition - Object format type
	 * [x1] defining type, 1 Absolute
	 */
	public static final int MUFOM_AD_TYPE = 0x26;

	/*
	 * Attribute Definition - Case sensitivity
	 * [x1] defining sensitivity, 2 Do not change the case of symbols
	 */
	public static final int MUFOM_AD_CASE = 0x27;

	/*
	 * Attribute Definition - Creation date and time
	 * [x1], [x2], [x3], [x4], [x5], [x6], year/month/day/hour/minute/second
	 * No ASN
	 */
	public static final int MUFOM_AD_DATETIME = 0x32;

	/*
	 * Attribute Definition - Command line text
	 * [id] command line
	 * No ASN
	 */
	public static final int MUFOM_AD_COMMANDLINE = 0x33;

	/*
	 * Attribute Definition - Execution status
	 * [x1] 0 Success
	 * No ASN
	 */
	public static final int MUFOM_AD_STATUS = 0x34;

	/*
	 * Attribute Definition - Host environment
	 * [x1]
	 * No ASN
	 */
	public static final int MUFOM_AD_ENV = 0x35;

	/*
	 * Attribute Definition - Tool and version number
	 * [x1], [x2], and [x3] (optional [x4] revision level) tool, version, revision
	 * No ASN
	 */
	public static final int MUFOM_AD_TOOLVERSION = 0x36;

	/*
	 * Attribute Definition - Comments
	 * [id] comments
	 * No ASN
	 */
	public static final int MUFOM_AD_COMMENT = 0x37;

	/*
	 * Attribute Definition - Procedure block misc
	 * [x1] [x2] pmisc type id number and number of additional MUFOM_AD_STRING or ASN
	 */
	public static final int MUFOM_AD_PROCEDURE_MISC = 0x3e;
	
	/*
	 * Attribute Definition - Variable misc
	 * [x1] [x2] vmisc type id number and number of additional MUFOM_AD_STRING or ASN
	 */
	public static final int MUFOM_AD_VARIABLE_MISC = 0x3f;
	
	/*
	 * Attribute Definition - Module misc
	 * [x1] [x2] mmisc type id number and number of additional MUFOM_AD_STRING or ASN
	 */
	public static final int MUFOM_AD_MODULE_MISC = 0x40;
	
	/*
	 * Attribute Definition - Misc string
	 * [id] miscellaneous string for MUFOM_AD_PROCEDURE, MUFOM_AD_VARIABLE, or MUFOM_AD_MODULE
	 */
	public static final int MUFOM_AD_MSTRING = 0x41;
	
	/* Built-in Types ?, unknown type, 'UNKNOWN TYPE' */
	public static final int MUFOM_BUILTIN_UNK = 0x00;

	/* Built-in Types void, procedure returning void, 'void' */
	public static final int MUFOM_BUILTIN_V = 0x01;

	/* Built-in Types byte, 8-bit signed, 'signed char' int8_t */
	public static final int MUFOM_BUILTIN_B = 0x02;

	/* Built-in Types char, 8-bit unsigned, 'unsigned char' uint8_t */
	public static final int MUFOM_BUILTIN_C = 0x03;

	/* Built-in Types halfword, 16-bit signed, 'signed short int' int16_t */
	public static final int MUFOM_BUILTIN_H = 0x04;

	/* Built-in Types int, 16-bit unsigned, 'unsigned short int' uint16_t */
	public static final int MUFOM_BUILTIN_I = 0x05;

	/* Built-in Types long, 32-bit signed, 'signed long' int32_t */
	public static final int MUFOM_BUILTIN_L = 0x06;

	/* Built-in Types , 32-bit unsigned, 'unsigned long' uint32_t */
	public static final int MUFOM_BUILTIN_M = 0x07;

	/* Built-in Types long int, 64-bit signed, 'signed long int' int64_t */
	public static final int MUFOM_BUILTIN_N = 0x08;

	/* Built-in Types , 64-bit unsigned, 'unsigned long int' uint64_t */
	public static final int MUFOM_BUILTIN_Q = 0x09;

	/* Built-in Types float, 32-bit floating point, 'float' */
	public static final int MUFOM_BUILTIN_F = 0x0a;

	/* Built-in Types double, 64-bit floating point, 'double' */
	public static final int MUFOM_BUILTIN_D = 0x0b;

	/* Built-in Types king size, extended precision floating point, 'long double' */
	public static final int MUFOM_BUILTIN_K = 0x0c;

	/* Built-in Types king size, 128-bit floating point, 'long double double' */
	public static final int MUFOM_BUILTIN_G = 0x0d;
	
	/* Built-in Types quoted string */
	public static final int MUFOM_BUILTIN_S = 0x0e;

	/* Built-in Types jump to, code location, 'instruction address' */
	public static final int MUFOM_BUILTIN_J = 0x0f;
	
	/* Built-in Types stack push */
	public static final int MUFOM_BUILTIN_SP0 = 0x10;
	
	/* Built-in Types stack push */
	public static final int MUFOM_BUILTIN_SP1 = 0x11;
	
	/* Built-in Types stack push */
	public static final int MUFOM_BUILTIN_SP2 = 0x12;
	
	/* 19 - 25 "alias for above" */
	
	/* Built-in Types 64-bit BCD float */
	public static final int MUFOM_BUILTIN_BCD = 0x19;

	/* Built-in Pointer Types ?, unknown type, 'UNKNOWN TYPE' */
	public static final int MUFOM_BUILTIN_PUNK = 0x20;

	/* Built-in Pointer Types void, procedure returning void, 'void' */
	public static final int MUFOM_BUILTIN_PV = 0x21;

	/* Built-in Pointer Types byte, 8-bit signed, 'signed char' */
	public static final int MUFOM_BUILTIN_PB = 0x22;

	/* Built-in Pointer Types char, 8-bit unsigned, 'unsigned char' */
	public static final int MUFOM_BUILTIN_PC = 0x23;

	/* Built-in Pointer Types halfword, 16-bit signed, 'signed short int' */
	public static final int MUFOM_BUILTIN_PH = 0x24;

	/* Built-in Pointer Types int, 16-bit unsigned, 'unsigned short int' */
	public static final int MUFOM_BUILTIN_PI = 0x25;

	/* Built-in Pointer Types long, 32-bit signed, 'signed long' */
	public static final int MUFOM_BUILTIN_PL = 0x26;

	/* Built-in Pointer Types , 32-bit unsigned, 'unsigned long' */
	public static final int MUFOM_BUILTIN_PM = 0x27;
	
	/* Built-in Types long int, 64-bit signed, 'signed long int' int64_t */
	public static final int MUFOM_BUILTIN_PN = 0x28;

	/* Built-in Types , 64-bit unsigned, 'unsigned long int' uint64_t */
	public static final int MUFOM_BUILTIN_PQ = 0x29;

	/* Built-in Pointer Types float, 32-bit floating point, 'float' */
	public static final int MUFOM_BUILTIN_PF = 0x2a;

	/* Built-in Pointer Types double, 64-bit floating point, 'double' */
	public static final int MUFOM_BUILTIN_PD = 0x2b;

	/* Built-in Pointer Types king size, extended precision floating point, 'long double' */
	public static final int MUFOM_BUILTIN_PK = 0x2c;
	
	/* Built-in Types king size, 128-bit floating point, 'long double double' */
	public static final int MUFOM_BUILTIN_PG = 0x2d;
	
	/* Built-in Types quoted string */
	public static final int MUFOM_BUILTIN_PS = 0x2e;

	/* Built-in Types jump to, code location, 'instruction address' */
	public static final int MUFOM_BUILTIN_PJ = 0x2f;
	
	/* Built-in Types stack push */
	public static final int MUFOM_BUILTIN_PSP0 = 0x30;
	
	/* Built-in Types stack push */
	public static final int MUFOM_BUILTIN_PSP1 = 0x31;
	
	/* Built-in Types stack push */
	public static final int MUFOM_BUILTIN_PSP2 = 0x32;
	
	/* 51 - 56 "p.alias for above" */
	
	/* Built-in Types 64-bit BCD float */
	public static final int MUFOM_BUILTIN_PBCD = 0x39;
	
	/* Assign Value to Variable W0 (ASW0) - AD Extension Part*/
	public static final int MUFOM_PT_ADX = 0x00;

	/* Assign Value to Variable W1 (ASW1) - Environment Part */
	public static final int MUFOM_PT_ENV = 0x01;

	/* Assign Value to Variable W2 (ASW2) - Section Definition Part */
	public static final int MUFOM_PT_SEC = 0x02;

	/* Assign Value to Variable W3 (ASW3) - External Part */
	public static final int MUFOM_PT_EXT = 0x03;

	/* Assign Value to Variable W4 (ASW4) - Debug Information Definition Part */
	public static final int MUFOM_PT_DEBUG = 0x04;

	/* Assign Value to Variable W5 (ASW5) - Data Part */
	public static final int MUFOM_PT_DATA = 0x05;

	/* Assign Value to Variable W6 (ASW6) - Trailer Part */
	public static final int MUFOM_PT_TRAIL = 0x06;

	/* Assign Value to Variable W7 (ASW7) */
	public static final int MUFOM_ASW7 = 0x07;

	/* Block Type - dummy bottom of the stack */
	public static final int MUFOM_DBLK_BOTTOM = 0x00;

	/* Block Type - unique type definitions for module */
	public static final int MUFOM_DBLK_MTDEF = 0x01;
	
	/* Block Type - global unique type definitions */
	public static final int MUFOM_DBLK_GTDEF = 0x02;
	
	/* Block Type - high level module scope beginning */
	public static final int MUFOM_DBLK_MSCOPE = 0x03;
	
	/* Block Type - global function */
	public static final int MUFOM_DBLK_GFUNC = 0x04;
	
	/* Block Type - filename for source line numbers */
	public static final int MUFOM_DBLK_SLINE = 0x05;
	
	/* Block Type - local function */
	public static final int MUFOM_DBLK_LFUNC = 0x06;
	
	/* Block Type - assembler module scope beginning */
	public static final int MUFOM_DBLK_ASMSC = 0x0a;
	
	/* Block Type - module section */
	public static final int MUFOM_DBLK_MODSEC = 0x0b;
	
	/* Complex Type '!' - Unkown type (sized) */
	public static final int MUFOM_CT_UNKNOWN = 0x21;

	/* Complex Type 'A' - array */
	public static final int MUFOM_CT_ARRAY = 0x41;

	/* Complex Type 'E' - simple enumeration */
	public static final int MUFOM_CT_SIMPLE_ENUM = 0x45;
	
	/* Complex Type 'G' - Struct with Bit-field */
	public static final int MUFOM_CT_STRUCT_BITFIELD = 0x57;

	/* Complex Type 'N' - generalized C enumeration */
	public static final int MUFOM_CT_ENUMUMERATION = 0x4e;

	/* Complex Type '0' - small pointer to another type */
	public static final int MUFOM_CT_SMALL_POINTER = 0x4f;

	/* Complex Type 'P' - (large) 32-bit pointer to another type */
	public static final int MUFOM_CT_LARGE_POINTER = 0x50;

	/* Complex Type 'R' - range */
	public static final int MUFOM_CT_RANGE = 0x52;

	/* Complex Type 'S' - data structure */
	public static final int MUFOM_CT_STRUCTURE = 0x53;

	/* Complex Type 'T' - typedef */
	public static final int MUFOM_CT_TYPEDEF = 0x54;

	/* Complex Type 'U' - union of members */
	public static final int MUFOM_CT_UNION = 0x55;
	
	/* Complex Type 'V' - void */
	public static final int MUFOM_CT_VOID = 0x56;
	
	/* Complex Type 'X' - procedure, extern declaration */
	public static final int MUFOM_CT_DECLARATION = 0x58;
	
	/* Complex Type 'Z' - C array with lower bound = 0 (zero based) */
	public static final int MUFOM_CT_ARRAYZ = 0x5a;
	
	/* Complex Type 'a' - FORTRAN array in column/row order */
	public static final int MUFOM_CT_FORTRAN_ARRAY = 0x61;

	/* Complex Type 'c' - complex */
	public static final int MUFOM_CT_COMPLEX = 0x63;
	
	/* Complex Type 'd' - double complex */
	public static final int MUFOM_CT_DOUBLE_COMPLEX = 0x64;
	
	/* Complex Type 'f' - Pascal file name */
	public static final int MUFOM_CT_PASCAL_FNAME = 0x66;

	/* Complex Type 'g' - Bit-field */
	public static final int MUFOM_CT_BITFIELD = 0x67;
	
	//TODO  what is this
	/* Complex Type 'm' - */
	public static final int MUFOM_CT_M = 0x6d;

	/* Complex Type 'n' - qualifier */
	public static final int MUFOM_CT_QUALIFIER = 0x6e;

	/* Complex Type 's' - set */
	public static final int MUFOM_CT_SET = 0x73;

	/* Complex Type 'x' - procedure with compiler dependencies */
	public static final int MUFOM_CT_PROCEDURE = 0x78;
	
	/* Misc Type Identification - Compiler ID */
	public static final int MUFOM_MISC_COMPILERID = 0x32;
	
	public static final int ieee_unknown_56_enum = 0x38;

	public static final int ieee_record_seperator_enum = 0xdb;

	public static final int ieee_attribute_record_enum = 0xc9;
	
}
