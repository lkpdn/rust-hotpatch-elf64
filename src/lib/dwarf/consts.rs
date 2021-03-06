use lib::dwarf::*;
/*
 * Format and debugging information
 */
pub const DW_TAG_ARRAY_TYPE : DW_TAG = DW_TAG(0x01);
pub const DW_TAG_CLASS_TYPE : DW_TAG = DW_TAG(0x02);
pub const DW_TAG_ENTRY_POINT : DW_TAG = DW_TAG(0x03);
pub const DW_TAG_ENUMERATION_TYPE : DW_TAG = DW_TAG(0x04);
pub const DW_TAG_FORMAL_PARAMETER : DW_TAG = DW_TAG(0x05);
pub const DW_TAG_IMPORTED_DECLARATION : DW_TAG = DW_TAG(0x08);
pub const DW_TAG_LABEL : DW_TAG = DW_TAG(0x0a);
pub const DW_TAG_LEXICAL_BLOCK : DW_TAG = DW_TAG(0x0b);
pub const DW_TAG_MEMBER : DW_TAG = DW_TAG(0x0d);
pub const DW_TAG_POINTER_TYPE : DW_TAG = DW_TAG(0x0f);
pub const DW_TAG_REFERENCE_TYPE : DW_TAG = DW_TAG(0x10);
pub const DW_TAG_COMPILE_UNIT : DW_TAG = DW_TAG(0x11);
pub const DW_TAG_STRING_TYPE : DW_TAG = DW_TAG(0x12);
pub const DW_TAG_STRUCTURE_TYPE : DW_TAG = DW_TAG(0x13);
pub const DW_TAG_SUBROUTINE_TYPE : DW_TAG = DW_TAG(0x15);
pub const DW_TAG_TYPEDEF : DW_TAG = DW_TAG(0x16);
pub const DW_TAG_UNION_TYPE : DW_TAG = DW_TAG(0x17);
pub const DW_TAG_UNSPECIFIED_PARAMETERS : DW_TAG = DW_TAG(0x18);
pub const DW_TAG_VARIANT : DW_TAG = DW_TAG(0x19);
pub const DW_TAG_COMMON_BLOCK : DW_TAG = DW_TAG(0x1a);
pub const DW_TAG_COMMON_INCLUSION : DW_TAG = DW_TAG(0x1b);
pub const DW_TAG_INHERITANCE : DW_TAG = DW_TAG(0x1c);
pub const DW_TAG_INLINED_SUBROUTINE : DW_TAG = DW_TAG(0x1d);
pub const DW_TAG_MODULE : DW_TAG = DW_TAG(0x1e);
pub const DW_TAG_PTR_TO_MEMBER_TYPE : DW_TAG = DW_TAG(0x1f);
pub const DW_TAG_SET_TYPE : DW_TAG = DW_TAG(0x20);
pub const DW_TAG_SUBRANGE_TYPE : DW_TAG = DW_TAG(0x21);
pub const DW_TAG_WITH_STMT : DW_TAG = DW_TAG(0x22);
pub const DW_TAG_ACCESS_DECLARATION : DW_TAG = DW_TAG(0x23);
pub const DW_TAG_BASE_TYPE : DW_TAG = DW_TAG(0x24);
pub const DW_TAG_CATCH_BLOCK : DW_TAG = DW_TAG(0x25);
pub const DW_TAG_CONST_TYPE : DW_TAG = DW_TAG(0x26);
pub const DW_TAG_CONSTANT : DW_TAG = DW_TAG(0x27);
pub const DW_TAG_ENUMERATOR : DW_TAG = DW_TAG(0x28);
pub const DW_TAG_FILE_TYPE : DW_TAG = DW_TAG(0x29);
pub const DW_TAG_FRIEND : DW_TAG = DW_TAG(0x2a);
pub const DW_TAG_NAMELIST : DW_TAG = DW_TAG(0x2b);
pub const DW_TAG_NAMELIST_ITEM : DW_TAG = DW_TAG(0x2c);
pub const DW_TAG_PACKED_TYPE : DW_TAG = DW_TAG(0x2d);
pub const DW_TAG_SUBPROGRAM : DW_TAG = DW_TAG(0x2e);
pub const DW_TAG_TEMPLATE_TYPE_PARAMETER : DW_TAG = DW_TAG(0x2f);
pub const DW_TAG_TEMPLATE_VALUE_PARAMETER : DW_TAG = DW_TAG(0x30);
pub const DW_TAG_THROWN_TYPE : DW_TAG = DW_TAG(0x31);
pub const DW_TAG_TRY_BLOCK : DW_TAG = DW_TAG(0x32);
pub const DW_TAG_VARIANT_PART : DW_TAG = DW_TAG(0x33);
pub const DW_TAG_VARIABLE : DW_TAG = DW_TAG(0x34);
pub const DW_TAG_VOLATILE_TYPE : DW_TAG = DW_TAG(0x35);
pub const DW_TAG_DWARF_PROCEDURE : DW_TAG = DW_TAG(0x36);
pub const DW_TAG_RESTRICT_TYPE : DW_TAG = DW_TAG(0x37);
pub const DW_TAG_INTERFACE_TYPE : DW_TAG = DW_TAG(0x38);
pub const DW_TAG_NAMESPACE : DW_TAG = DW_TAG(0x39);
pub const DW_TAG_IMPORTED_MODULE : DW_TAG = DW_TAG(0x3a);
pub const DW_TAG_UNSPECIFIED_TYPE : DW_TAG = DW_TAG(0x3b);
pub const DW_TAG_PARTIAL_UNIT : DW_TAG = DW_TAG(0x3c);
pub const DW_TAG_IMPORTED_UNIT : DW_TAG = DW_TAG(0x3d);
pub const DW_TAG_CONDITION : DW_TAG = DW_TAG(0x3f);
pub const DW_TAG_SHARED_TYPE : DW_TAG = DW_TAG(0x40);
pub const DW_TAG_TYPE_UNIT : DW_TAG = DW_TAG(0x41);
pub const DW_TAG_RVALUE_REFERENCE_TYPE : DW_TAG = DW_TAG(0x42);
pub const DW_TAG_TEMPLATE_ALIAS : DW_TAG = DW_TAG(0x43);
pub const DW_TAG_LO_USER : DW_TAG = DW_TAG(0x4080);
pub const DW_TAG_HI_USER : DW_TAG = DW_TAG(0xffff);

pub const DW_CHILDREN_NO : DW_CHILDREN = DW_CHILDREN(0x00);
pub const DW_CHILDREN_YES : DW_CHILDREN = DW_CHILDREN(0x01);

pub const DW_AT_SIBLING : DW_AT = DW_AT(0x01);
pub const DW_AT_LOCATION : DW_AT = DW_AT(0x02);
pub const DW_AT_NAME : DW_AT = DW_AT(0x03);
pub const DW_AT_ORDERING : DW_AT = DW_AT(0x09);
pub const DW_AT_BYTE_SIZE : DW_AT = DW_AT(0x0b);
pub const DW_AT_BIT_OFFSET : DW_AT = DW_AT(0x0c);
pub const DW_AT_BIT_SIZE : DW_AT = DW_AT(0x0d);
pub const DW_AT_STMT_LIST : DW_AT = DW_AT(0x10);
pub const DW_AT_LOW_PC : DW_AT = DW_AT(0x11);
pub const DW_AT_HIGH_PC : DW_AT = DW_AT(0x12);
pub const DW_AT_LANGUAGE : DW_AT = DW_AT(0x13);
pub const DW_AT_DISCR : DW_AT = DW_AT(0x15);
pub const DW_AT_DISCR_VALUE : DW_AT = DW_AT(0x16);
pub const DW_AT_VISIBILITY : DW_AT = DW_AT(0x17);
pub const DW_AT_IMPORT : DW_AT = DW_AT(0x18);
pub const DW_AT_STRING_LENGTH : DW_AT = DW_AT(0x19);
pub const DW_AT_COMMON_REFERENCE : DW_AT = DW_AT(0x1a);
pub const DW_AT_COMP_DIR : DW_AT = DW_AT(0x1b);
pub const DW_AT_CONST_VALUE : DW_AT = DW_AT(0x1c);
pub const DW_AT_CONTAINING_TYPE : DW_AT = DW_AT(0x1d);
pub const DW_AT_DEFAULT_VALUE : DW_AT = DW_AT(0x1e);
pub const DW_AT_INLINE : DW_AT = DW_AT(0x20);
pub const DW_AT_IS_OPTIONAL : DW_AT = DW_AT(0x21);
pub const DW_AT_LOWER_BOUND : DW_AT = DW_AT(0x22);
pub const DW_AT_PRODUCER : DW_AT = DW_AT(0x25);
pub const DW_AT_PROTOTYPED : DW_AT = DW_AT(0x27);
pub const DW_AT_RETURN_ADDR : DW_AT = DW_AT(0x2a);
pub const DW_AT_START_SCOPE : DW_AT = DW_AT(0x2c);
pub const DW_AT_BIT_STRIDE : DW_AT = DW_AT(0x2e);
pub const DW_AT_UPPER_BOUND : DW_AT = DW_AT(0x2f);
pub const DW_AT_ABSTRACT_ORIGIN : DW_AT = DW_AT(0x31);
pub const DW_AT_ACCESSIBILITY : DW_AT = DW_AT(0x32);
pub const DW_AT_ADDRESS_CLASS : DW_AT = DW_AT(0x33);
pub const DW_AT_ARTIFICIAL : DW_AT = DW_AT(0x34);
pub const DW_AT_BASE_TYPES : DW_AT = DW_AT(0x35);
pub const DW_AT_CALLING_CONVENTION : DW_AT = DW_AT(0x36);
pub const DW_AT_COUNT : DW_AT = DW_AT(0x37);
pub const DW_AT_DATA_MEMBER_LOCATION : DW_AT = DW_AT(0x38);
pub const DW_AT_DECL_COLUMN : DW_AT = DW_AT(0x39);
pub const DW_AT_DECL_FILE : DW_AT = DW_AT(0x3a);
pub const DW_AT_DECL_LINE : DW_AT = DW_AT(0x3b);
pub const DW_AT_DECLARATION : DW_AT = DW_AT(0x3c);
pub const DW_AT_DISCR_LIST : DW_AT = DW_AT(0x3d);
pub const DW_AT_ENCODING : DW_AT = DW_AT(0x3e);
pub const DW_AT_EXTERNAL : DW_AT = DW_AT(0x3f);
pub const DW_AT_FRAME_BASE : DW_AT = DW_AT(0x40);
pub const DW_AT_FRIEND : DW_AT = DW_AT(0x41);
pub const DW_AT_IDENTIFIER_CASE : DW_AT = DW_AT(0x42);
pub const DW_AT_MACRO_INFO : DW_AT = DW_AT(0x43);
pub const DW_AT_NAMELIST_ITEM : DW_AT = DW_AT(0x44);
pub const DW_AT_PRIORITY : DW_AT = DW_AT(0x45);
pub const DW_AT_SEGMENT : DW_AT = DW_AT(0x46);
pub const DW_AT_SPECIFICATION : DW_AT = DW_AT(0x47);
pub const DW_AT_STATIC_LINK : DW_AT = DW_AT(0x48);
pub const DW_AT_TYPE : DW_AT = DW_AT(0x49);
pub const DW_AT_USE_LOCATION : DW_AT = DW_AT(0x4a);
pub const DW_AT_VARIABLE_PARAMETER : DW_AT = DW_AT(0x4b);
pub const DW_AT_VIRTUALITY : DW_AT = DW_AT(0x4c);
pub const DW_AT_VTABLE_ELEM_LOCATION : DW_AT = DW_AT(0x4d);
pub const DW_AT_ALLOCATED : DW_AT = DW_AT(0x4e);
pub const DW_AT_ASSOCIATED : DW_AT = DW_AT(0x4f);
pub const DW_AT_DATA_LOCATION : DW_AT = DW_AT(0x50);
pub const DW_AT_BYTE_STRIDE : DW_AT = DW_AT(0x51);
pub const DW_AT_ENTRY_PC : DW_AT = DW_AT(0x52);
pub const DW_AT_USE_UTF8 : DW_AT = DW_AT(0x53);
pub const DW_AT_EXTENSION : DW_AT = DW_AT(0x54);
pub const DW_AT_RANGES : DW_AT = DW_AT(0x55);
pub const DW_AT_TRAMPOLINE : DW_AT = DW_AT(0x56);
pub const DW_AT_CALL_COLUMN : DW_AT = DW_AT(0x57);
pub const DW_AT_CALL_FILE : DW_AT = DW_AT(0x58);
pub const DW_AT_CALL_LINE : DW_AT = DW_AT(0x59);
pub const DW_AT_DESCRIPTION : DW_AT = DW_AT(0x5a);
pub const DW_AT_BINARY_SCALE : DW_AT = DW_AT(0x5b);
pub const DW_AT_DECIMAL_SCALE : DW_AT = DW_AT(0x5c);
pub const DW_AT_SMALL : DW_AT = DW_AT(0x5d);
pub const DW_AT_DECIMAL_SIGN : DW_AT = DW_AT(0x5e);
pub const DW_AT_DIGIT_COUNT : DW_AT = DW_AT(0x5f);
pub const DW_AT_PICTURE_STRING : DW_AT = DW_AT(0x60);
pub const DW_AT_MUTABLE : DW_AT = DW_AT(0x61);
pub const DW_AT_THREADS_SCALED : DW_AT = DW_AT(0x62);
pub const DW_AT_EXPLICIT : DW_AT = DW_AT(0x63);
pub const DW_AT_OBJECT_POINTER : DW_AT = DW_AT(0x64);
pub const DW_AT_ENDIANITY : DW_AT = DW_AT(0x65);
pub const DW_AT_ELEMENTAL : DW_AT = DW_AT(0x66);
pub const DW_AT_PURE_FLAG : DW_AT = DW_AT(0x67);
pub const DW_AT_RECURSIVE : DW_AT = DW_AT(0x68);
pub const DW_AT_SIGNATURE : DW_AT = DW_AT(0x69);
pub const DW_AT_MAIN_SUBPROGRAM : DW_AT = DW_AT(0x6a);
pub const DW_AT_DATA_BIT_OFFSET : DW_AT = DW_AT(0x6b);
pub const DW_AT_CONST_EXPR : DW_AT = DW_AT(0x6c);
pub const DW_AT_ENUM_CLASS : DW_AT = DW_AT(0x6d);
pub const DW_AT_LINKAGE_NAME : DW_AT = DW_AT(0x6e);
pub const DW_AT_LO_USER : DW_AT = DW_AT(0x2000);
pub const DW_AT_HI_USER : DW_AT = DW_AT(0x3fff);

pub const DW_FORM_ADDR : DW_FORM = DW_FORM(0x01);
pub const DW_FORM_BLOCK2 : DW_FORM = DW_FORM(0x03);
pub const DW_FORM_BLOCK4 : DW_FORM = DW_FORM(0x04);
pub const DW_FORM_DATA2 : DW_FORM = DW_FORM(0x05);
pub const DW_FORM_DATA4 : DW_FORM = DW_FORM(0x06);
pub const DW_FORM_DATA8 : DW_FORM = DW_FORM(0x07);
pub const DW_FORM_STRING : DW_FORM = DW_FORM(0x08);
pub const DW_FORM_BLOCK : DW_FORM = DW_FORM(0x09);
pub const DW_FORM_BLOCK1 : DW_FORM = DW_FORM(0x0a);
pub const DW_FORM_DATA1 : DW_FORM = DW_FORM(0x0b);
pub const DW_FORM_FLAG : DW_FORM = DW_FORM(0x0c);
pub const DW_FORM_SDATA : DW_FORM = DW_FORM(0x0d);
pub const DW_FORM_STRP : DW_FORM = DW_FORM(0x0e);
pub const DW_FORM_UDATA : DW_FORM = DW_FORM(0x0f);
pub const DW_FORM_REF_ADDR : DW_FORM = DW_FORM(0x10);
pub const DW_FORM_REF1 : DW_FORM = DW_FORM(0x11);
pub const DW_FORM_REF2 : DW_FORM = DW_FORM(0x12);
pub const DW_FORM_REF4 : DW_FORM = DW_FORM(0x13);
pub const DW_FORM_REF8 : DW_FORM = DW_FORM(0x14);
pub const DW_FORM_REF_UDATA : DW_FORM = DW_FORM(0x15);
pub const DW_FORM_INDIRECT : DW_FORM = DW_FORM(0x16);
pub const DW_FORM_SEC_OFFSET : DW_FORM = DW_FORM(0x17);
pub const DW_FORM_EXPRLOC : DW_FORM = DW_FORM(0x18);
pub const DW_FORM_FLAG_PRESENT : DW_FORM = DW_FORM(0x19);
pub const DW_FORM_REF_SIG8 : DW_FORM = DW_FORM(0x20);

pub const DW_OP_ADDR : DW_OP = DW_OP(0x03);
pub const DW_OP_DEREF : DW_OP = DW_OP(0x06);
pub const DW_OP_CONST1U : DW_OP = DW_OP(0x08);
pub const DW_OP_CONST1S : DW_OP = DW_OP(0x09);
pub const DW_OP_CONST2U : DW_OP = DW_OP(0x0a);
pub const DW_OP_CONST2S : DW_OP = DW_OP(0x0b);
pub const DW_OP_CONST4U : DW_OP = DW_OP(0x0c);
pub const DW_OP_CONST4S : DW_OP = DW_OP(0x0d);
pub const DW_OP_CONST8U : DW_OP = DW_OP(0x0e);
pub const DW_OP_CONST8S : DW_OP = DW_OP(0x0f);
pub const DW_OP_CONSTU : DW_OP = DW_OP(0x10);
pub const DW_OP_CONSTS : DW_OP = DW_OP(0x11);
pub const DW_OP_DUP : DW_OP = DW_OP(0x12);
pub const DW_OP_DROP : DW_OP = DW_OP(0x13);
pub const DW_OP_OVER : DW_OP = DW_OP(0x14);
pub const DW_OP_PICK : DW_OP = DW_OP(0x15);
pub const DW_OP_SWAP : DW_OP = DW_OP(0x16);
pub const DW_OP_ROT : DW_OP = DW_OP(0x17);
pub const DW_OP_XDEREF : DW_OP = DW_OP(0x18);
pub const DW_OP_ABS : DW_OP = DW_OP(0x19);
pub const DW_OP_AND : DW_OP = DW_OP(0x1a);
pub const DW_OP_DIV : DW_OP = DW_OP(0x1b);
pub const DW_OP_MINUS : DW_OP = DW_OP(0x1c);
pub const DW_OP_MOD : DW_OP = DW_OP(0x1d);
pub const DW_OP_MUL : DW_OP = DW_OP(0x1e);
pub const DW_OP_NEG : DW_OP = DW_OP(0x1f);
pub const DW_OP_NOT : DW_OP = DW_OP(0x20);
pub const DW_OP_OR : DW_OP = DW_OP(0x21);
pub const DW_OP_PLUS : DW_OP = DW_OP(0x22);
pub const DW_OP_PLUS_UCONST : DW_OP = DW_OP(0x23);
pub const DW_OP_SHL : DW_OP = DW_OP(0x24);
pub const DW_OP_SHR : DW_OP = DW_OP(0x25);
pub const DW_OP_SHRA : DW_OP = DW_OP(0x26);
pub const DW_OP_XOR : DW_OP = DW_OP(0x27);
pub const DW_OP_SKIP : DW_OP = DW_OP(0x2f);
pub const DW_OP_BRA : DW_OP = DW_OP(0x28);
pub const DW_OP_EQ : DW_OP = DW_OP(0x29);
pub const DW_OP_GE : DW_OP = DW_OP(0x2a);
pub const DW_OP_GT : DW_OP = DW_OP(0x2b);
pub const DW_OP_LE : DW_OP = DW_OP(0x2c);
pub const DW_OP_LT : DW_OP = DW_OP(0x2d);
pub const DW_OP_NE : DW_OP = DW_OP(0x2e);
pub const DW_OP_LIT0 : DW_OP = DW_OP(0x30);
pub const DW_OP_LIT1 : DW_OP = DW_OP(0x31);
pub const DW_OP_LIT2 : DW_OP = DW_OP(0x32);
pub const DW_OP_LIT3 : DW_OP = DW_OP(0x33);
pub const DW_OP_LIT4 : DW_OP = DW_OP(0x34);
pub const DW_OP_LIT5 : DW_OP = DW_OP(0x35);
pub const DW_OP_LIT6 : DW_OP = DW_OP(0x36);
pub const DW_OP_LIT7 : DW_OP = DW_OP(0x37);
pub const DW_OP_LIT8 : DW_OP = DW_OP(0x38);
pub const DW_OP_LIT9 : DW_OP = DW_OP(0x39);
pub const DW_OP_LIT10 : DW_OP = DW_OP(0x3a);
pub const DW_OP_LIT11 : DW_OP = DW_OP(0x3b);
pub const DW_OP_LIT12 : DW_OP = DW_OP(0x3c);
pub const DW_OP_LIT13 : DW_OP = DW_OP(0x3d);
pub const DW_OP_LIT14 : DW_OP = DW_OP(0x3e);
pub const DW_OP_LIT15 : DW_OP = DW_OP(0x3f);
pub const DW_OP_LIT16 : DW_OP = DW_OP(0x40);
pub const DW_OP_LIT17 : DW_OP = DW_OP(0x41);
pub const DW_OP_LIT18 : DW_OP = DW_OP(0x42);
pub const DW_OP_LIT19 : DW_OP = DW_OP(0x43);
pub const DW_OP_LIT20 : DW_OP = DW_OP(0x44);
pub const DW_OP_LIT21 : DW_OP = DW_OP(0x45);
pub const DW_OP_LIT22 : DW_OP = DW_OP(0x46);
pub const DW_OP_LIT23 : DW_OP = DW_OP(0x47);
pub const DW_OP_LIT24 : DW_OP = DW_OP(0x48);
pub const DW_OP_LIT25 : DW_OP = DW_OP(0x49);
pub const DW_OP_LIT26 : DW_OP = DW_OP(0x4a);
pub const DW_OP_LIT27 : DW_OP = DW_OP(0x4b);
pub const DW_OP_LIT28 : DW_OP = DW_OP(0x4c);
pub const DW_OP_LIT29 : DW_OP = DW_OP(0x4d);
pub const DW_OP_LIT30 : DW_OP = DW_OP(0x4e);
pub const DW_OP_LIT31 : DW_OP = DW_OP(0x4f);
pub const DW_OP_REG0 : DW_OP = DW_OP(0x50);
pub const DW_OP_REG1 : DW_OP = DW_OP(0x51);
pub const DW_OP_REG2 : DW_OP = DW_OP(0x52);
pub const DW_OP_REG3 : DW_OP = DW_OP(0x53);
pub const DW_OP_REG4 : DW_OP = DW_OP(0x54);
pub const DW_OP_REG5 : DW_OP = DW_OP(0x55);
pub const DW_OP_REG6 : DW_OP = DW_OP(0x56);
pub const DW_OP_REG7 : DW_OP = DW_OP(0x57);
pub const DW_OP_REG8 : DW_OP = DW_OP(0x58);
pub const DW_OP_REG9 : DW_OP = DW_OP(0x59);
pub const DW_OP_REG10 : DW_OP = DW_OP(0x5a);
pub const DW_OP_REG11 : DW_OP = DW_OP(0x5b);
pub const DW_OP_REG12 : DW_OP = DW_OP(0x5c);
pub const DW_OP_REG13 : DW_OP = DW_OP(0x5d);
pub const DW_OP_REG14 : DW_OP = DW_OP(0x5e);
pub const DW_OP_REG15 : DW_OP = DW_OP(0x5f);
pub const DW_OP_REG16 : DW_OP = DW_OP(0x60);
pub const DW_OP_REG17 : DW_OP = DW_OP(0x61);
pub const DW_OP_REG18 : DW_OP = DW_OP(0x62);
pub const DW_OP_REG19 : DW_OP = DW_OP(0x63);
pub const DW_OP_REG20 : DW_OP = DW_OP(0x64);
pub const DW_OP_REG21 : DW_OP = DW_OP(0x65);
pub const DW_OP_REG22 : DW_OP = DW_OP(0x66);
pub const DW_OP_REG23 : DW_OP = DW_OP(0x67);
pub const DW_OP_REG24 : DW_OP = DW_OP(0x68);
pub const DW_OP_REG25 : DW_OP = DW_OP(0x69);
pub const DW_OP_REG26 : DW_OP = DW_OP(0x6a);
pub const DW_OP_REG27 : DW_OP = DW_OP(0x6b);
pub const DW_OP_REG28 : DW_OP = DW_OP(0x6c);
pub const DW_OP_REG29 : DW_OP = DW_OP(0x6d);
pub const DW_OP_REG30 : DW_OP = DW_OP(0x6e);
pub const DW_OP_REG31 : DW_OP = DW_OP(0x6f);
pub const DW_OP_BREG0 : DW_OP = DW_OP(0x70);
pub const DW_OP_BREG1 : DW_OP = DW_OP(0x71);
pub const DW_OP_BREG2 : DW_OP = DW_OP(0x72);
pub const DW_OP_BREG3 : DW_OP = DW_OP(0x73);
pub const DW_OP_BREG4 : DW_OP = DW_OP(0x74);
pub const DW_OP_BREG5 : DW_OP = DW_OP(0x75);
pub const DW_OP_BREG6 : DW_OP = DW_OP(0x76);
pub const DW_OP_BREG7 : DW_OP = DW_OP(0x77);
pub const DW_OP_BREG8 : DW_OP = DW_OP(0x78);
pub const DW_OP_BREG9 : DW_OP = DW_OP(0x79);
pub const DW_OP_BREG10 : DW_OP = DW_OP(0x7a);
pub const DW_OP_BREG11 : DW_OP = DW_OP(0x7b);
pub const DW_OP_BREG12 : DW_OP = DW_OP(0x7c);
pub const DW_OP_BREG13 : DW_OP = DW_OP(0x7d);
pub const DW_OP_BREG14 : DW_OP = DW_OP(0x7e);
pub const DW_OP_BREG15 : DW_OP = DW_OP(0x7f);
pub const DW_OP_BREG16 : DW_OP = DW_OP(0x80);
pub const DW_OP_BREG17 : DW_OP = DW_OP(0x81);
pub const DW_OP_BREG18 : DW_OP = DW_OP(0x82);
pub const DW_OP_BREG19 : DW_OP = DW_OP(0x83);
pub const DW_OP_BREG20 : DW_OP = DW_OP(0x84);
pub const DW_OP_BREG21 : DW_OP = DW_OP(0x85);
pub const DW_OP_BREG22 : DW_OP = DW_OP(0x86);
pub const DW_OP_BREG23 : DW_OP = DW_OP(0x87);
pub const DW_OP_BREG24 : DW_OP = DW_OP(0x88);
pub const DW_OP_BREG25 : DW_OP = DW_OP(0x89);
pub const DW_OP_BREG26 : DW_OP = DW_OP(0x8a);
pub const DW_OP_BREG27 : DW_OP = DW_OP(0x8b);
pub const DW_OP_BREG28 : DW_OP = DW_OP(0x8c);
pub const DW_OP_BREG29 : DW_OP = DW_OP(0x8d);
pub const DW_OP_BREG30 : DW_OP = DW_OP(0x8e);
pub const DW_OP_BREG31 : DW_OP = DW_OP(0x8f);
pub const DW_OP_REGX : DW_OP = DW_OP(0x90);
pub const DW_OP_FBREG : DW_OP = DW_OP(0x91);
pub const DW_OP_BREGX : DW_OP = DW_OP(0x92);
pub const DW_OP_PIECE : DW_OP = DW_OP(0x93);
pub const DW_OP_DEREF_SIZE : DW_OP = DW_OP(0x94);
pub const DW_OP_XDEREF_SIZE : DW_OP = DW_OP(0x95);
pub const DW_OP_NOP : DW_OP = DW_OP(0x96);
pub const DW_OP_PUSH_OBJECT_ADDRESS : DW_OP = DW_OP(0x97);
pub const DW_OP_CALL2 : DW_OP = DW_OP(0x98);
pub const DW_OP_CALL4 : DW_OP = DW_OP(0x99);
pub const DW_OP_CALL_REF : DW_OP = DW_OP(0x9a);
pub const DW_OP_FORM_TLS_ADDRESS : DW_OP = DW_OP(0x9b);
pub const DW_OP_CALL_FRAME_CFA : DW_OP = DW_OP(0x9c);
pub const DW_OP_BIT_PIECE : DW_OP = DW_OP(0x9d);
pub const DW_OP_IMPLICIT_VALUE : DW_OP = DW_OP(0x9e);
pub const DW_OP_STACK_VALUE : DW_OP = DW_OP(0x9f);
pub const DW_OP_LO_USER : DW_OP = DW_OP(0xe0);
pub const DW_OP_HI_USER : DW_OP = DW_OP(0xff);
