use std::io;

#[derive(Debug, Clone, Copy)]
pub struct CompilationUnitHeader {
    pub unit_length: u64,
    pub version: u16,
    pub debug_abbrev_offset: u64,
    pub address_size: u8,
}

#[derive(Debug, Clone)]
pub struct AbbrevDecls {
    pub decls: Vec<AbbrevDecl>,
}

impl AbbrevDecls {
    pub fn from_debug_abbrev(debug_abbrev: Vec<u8>) -> AbbrevDecls {
        let mut vc = debug_abbrev.clone();
        let mut decls: Vec<AbbrevDecl> = Vec::new();
        while vc.len() > 13 { // code + tag + children = 13
            let decl = AbbrevDecl::from_slice(&vc);
            let size = decl.size;
            decls.push(decl);
            vc.drain(0..size);
        }
        AbbrevDecls { decls: decls }
    }
    pub fn search_by_code(&self, code: u64) -> Result<&AbbrevDecl, ::GenError> {
        self.decls.iter().by_ref()
          .find(|e| e.code == code)
          .ok_or(::GenError::Plain(format!("AbbrevDecls: `code: {}` not found", code)))
    }
}

#[derive(Debug, Clone)]
pub struct AbbrevDecl {
    pub code: u64,
    pub tag: DW_TAG,
    pub children: DW_CHILDREN,
    pub attr_specs: Vec<AbbrevDeclAttrSpec>,
    pub size: usize,
}

impl AbbrevDecl {
    pub fn from_slice(sl: &[u8]) -> AbbrevDecl {
        let mut vc = sl.to_vec();
        let mut size = vc.len();
        let code = consume_leb128(&mut vc).unwrap();
        let tag = consume_leb128(&mut vc).unwrap() as u32;
        let children = consume_leb128(&mut vc).unwrap() as u8;
        let mut attr_specs: Vec<AbbrevDeclAttrSpec> = Vec::new();
        while vc.len() > 0 {
            let name = consume_leb128(&mut vc).unwrap() as u16;
            let form = consume_leb128(&mut vc).unwrap() as u16;
            if name == 0 && form == 0 { break }
            attr_specs.push(AbbrevDeclAttrSpec {
                name: DW_AT(name),
                form: DW_FORM(form),
            });
        }
        size -= vc.len();
        AbbrevDecl {
            code: code,
            tag: DW_TAG(tag),
            children: DW_CHILDREN(children),
            attr_specs: attr_specs,
            size: size,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AbbrevDeclAttrSpec {
    pub name: DW_AT,
    pub form: DW_FORM,
}

#[derive(Debug, Clone)]
pub struct FileNameTableEntry {
    pub entry: u8,
    pub dir: u8,
    pub time: u8,
    pub size: u8,
    pub name: String,
}

pub struct FileNameTable {
    pub entries: Vec<FileNameTableEntry>,
}

impl FileNameTable {
    pub fn from_debug_line(debug_line: Vec<u8>) -> FileNameTable {
        let mut opcode_base: u8 = 0;
        let sol_offset = match &debug_line[0..4] {
            // unit_length(12/4) + version(2/2) + header_length(8/4)
            // + minimum_instruction_length(1/1)
            // + default_is_stmt(1/1) + line_base(1/1) + line_range(1/1)
            // + opcode_base(1/1) + standard_opcode_lengths(LEB128 × (opcode_base -1))
            // + include_directories(sequence of null-terminated strings)
            &[0xff, 0xff, 0xff, 0xff] => {
                opcode_base = debug_line[26];
                12 + 2 + 8 + 1 + 1 + 1 + 1 + 1
            },
            _ => {
                opcode_base = debug_line[14];
                4 + 2 + 4 + 1 + 1 + 1 + 1 + 1
            }
        };
        let mut pile = debug_line.clone();

        // standard_opcode_lengths(LEB128 × (opcode_base -1))
        pile.drain(0..sol_offset);
        for i in 0..(opcode_base - 1) {
            consume_leb128(&mut pile);
        }
        let filenames_offset = pile.windows(2)
          .position(|w| w[0] == 0x00 && w[1] == 0x00)
          .unwrap() + 2;
        pile.drain(0..filenames_offset);
        FileNameTable::from_slice_of_table(&pile)
    }
    pub fn from_slice_of_table(sl: &[u8]) -> FileNameTable {
        let mut vc = sl.to_vec();
        let mut fname_index: u8 = 1; // refrenced index starts at one
        let mut entries: Vec<FileNameTableEntry> = Vec::new();
        loop {
            let terminator = vc.iter().position(|b| *b == 0x00).unwrap();
            if terminator == 0 { break }
            use std::str::from_utf8;
            let name = from_utf8(&vc[0..terminator]).unwrap().to_string();
            vc.drain(0..terminator);
            let dir = consume_leb128(&mut vc).unwrap() as u8;
            let time = consume_leb128(&mut vc).unwrap() as u8;
            let size = consume_leb128(&mut vc).unwrap() as u8;
            vc.remove(0);
            entries.push(FileNameTableEntry {
                entry: fname_index,
                dir: dir,
                time: time,
                size: size,
                name: name,
            });
            fname_index += 1;
        }
        FileNameTable { entries: entries }
    }
    pub fn search_filename(&self, filename: String) -> Result<&FileNameTableEntry, ::GenError> {
        self.entries.iter().by_ref()
          .find(|e| e.name == filename)
          .ok_or(::GenError::Plain(format!("FileNameTable.search_filename: `name: {}` not found", filename)))
    }
}

/*
 * Format and debugging information
 */
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DW_TAG(pub u32);
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DW_CHILDREN(pub u8);
pub const DW_CHILDREN_NO : DW_CHILDREN = DW_CHILDREN(0x00);
pub const DW_CHILDREN_YES : DW_CHILDREN = DW_CHILDREN(0x01);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DW_AT(pub u16);
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DW_FORM(pub u16);
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

impl DW_FORM {
    pub fn get_class(&self) -> CLASS {
        match *self {
            DW_FORM_ADDR => CLASS::ADDRESS,
            DW_FORM_BLOCK2 => CLASS::BLOCK,
            DW_FORM_BLOCK4 => CLASS::BLOCK,
            DW_FORM_DATA2 => CLASS::CONSTANT,
            DW_FORM_DATA4 => CLASS::CONSTANT,
            DW_FORM_DATA8 => CLASS::CONSTANT,
            DW_FORM_STRING => CLASS::STRING,
            DW_FORM_BLOCK => CLASS::BLOCK,
            DW_FORM_BLOCK1 => CLASS::BLOCK,
            DW_FORM_DATA1 => CLASS::CONSTANT,
            DW_FORM_FLAG => CLASS::FLAG,
            DW_FORM_SDATA => CLASS::CONSTANT,
            DW_FORM_STRP => CLASS::STRING,
            DW_FORM_UDATA => CLASS::CONSTANT,
            DW_FORM_REF_ADDR => CLASS::REFERENCE,
            DW_FORM_REF1 => CLASS::REFERENCE,
            DW_FORM_REF2 => CLASS::REFERENCE,
            DW_FORM_REF4 => CLASS::REFERENCE,
            DW_FORM_REF8 => CLASS::REFERENCE,
            DW_FORM_REF_UDATA => CLASS::REFERENCE,
            DW_FORM_INDIRECT => CLASS::UNKNOWN,
            DW_FORM_SEC_OFFSET => CLASS::UNKNOWN,
            DW_FORM_EXPRLOC => CLASS::EXPRLOC,
            DW_FORM_FLAG_PRESENT => CLASS::FLAG,
            DW_FORM_REF_SIG8 => CLASS::REFERENCE,
            _ => CLASS::UNKNOWN,
        }
    }
}

pub enum CLASS {
    ADDRESS,
    BLOCK,
    CONSTANT,
    EXPRLOC,
    FLAG,
    REFERENCE,
    STRING,
    UNKNOWN,
}

pub fn consume_leb128(v: &mut Vec<u8>) -> Result<u64, ::GenError> {
    let mut buf: Vec<u8> = vec![];
    loop {
        let read = v.remove(0);
        buf.push(read);
        if read & 0b1000_0000 == 0 { break }
    }
    let mut res: u64 = 0;
    let mut shift = 0;
    for b in &buf {
        res |= ((b & 0b0111_1111) as u64) << shift;
        shift += 7;
        if b & 0b1000_0000 == 0 { break }
    }
    Ok(res)
}

pub trait CursorExt {
    fn read_leb128(&mut self) -> Result<u64, ::GenError>;
}

impl CursorExt for io::Cursor<Vec<u8>> {
    fn read_leb128(&mut self) -> Result<u64, ::GenError> {
        // XXX: avoid inefficient cloning
        let position = self.position();
        let mut v: Vec<u8> = self.get_ref().clone();
        v.drain(0..position as usize);
        let mut size = v.len() as u64;
        let result = consume_leb128(&mut v).unwrap();
        size -= v.len() as u64;
        self.set_position(position + size);
        Ok(result)
    }
}

#[macro_export]
macro_rules! search_debug_info {
    (
        $data:ident,
        $abbrev_decls:ident,
        { DW_TAG => $tag:path,
        $($attr:path => $val:expr),* },
        $attr_to_get:expr,
        $val_type:ty
    ) => {{
        use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
        // consume header
        let mut rdr = io::Cursor::new($data.clone());
        let first_4bytes = rdr.read_u32::<LittleEndian>().unwrap();
        let compilation_unit_header = match first_4bytes {
            0xffff_ffff => {
                let unit_length = rdr.read_u64::<LittleEndian>().unwrap();
                let version = rdr.read_u16::<LittleEndian>().unwrap();
                let debug_abbrev_offset = rdr.read_u64::<LittleEndian>().unwrap();
                let address_size = rdr.read_u8().unwrap();
                CompilationUnitHeader {
                    unit_length: unit_length,
                    version: version,
                    debug_abbrev_offset: debug_abbrev_offset,
                    address_size: address_size,
                }
            },
            _ => {
                rdr.set_position(0);
                let unit_length = rdr.read_u32::<LittleEndian>().unwrap();
                let version = rdr.read_u16::<LittleEndian>().unwrap();
                let debug_abbrev_offset = rdr.read_u32::<LittleEndian>().unwrap();
                let address_size = rdr.read_u8().unwrap();
                CompilationUnitHeader {
                    unit_length: unit_length as u64,
                    version: version,
                    debug_abbrev_offset: debug_abbrev_offset as u64,
                    address_size: address_size,
                }
            }
        };

        // XXX: avoid inefficient loop and match
        let result: Vec<$val_type> = Vec::new();
        loop {
            let abbrev_number = rdr.read_leb128().unwrap();
            if rdr.position() == rdr.get_ref().len() as u64 { break }
            let abbrev_decl: &AbbrevDecl = $abbrev_decls.search_by_code(abbrev_number).unwrap();
            let tag: DW_TAG = abbrev_decl.tag;
            let mut skip: bool = false;
            if tag != $tag { skip = true }
            for attr_spec in &abbrev_decl.attr_specs {
                let name: DW_AT = attr_spec.name;
                let form: DW_FORM = attr_spec.form;
                let klass = form.get_class();
                $(
                match klass {
                    CLASS::ADDRESS   => {
                        let read_size = compilation_unit_header.address_size;
                        if !skip && $attr == name {
                            let mut val: u64 = 0;
                            match read_size {
                                1 => { val = rdr.read_u8().unwrap() as u64 },
                                2 => { val = rdr.read_u16::<LittleEndian>().unwrap() as u64 },
                                4 => { val = rdr.read_u32::<LittleEndian>().unwrap() as u64 },
                                8 => { val = rdr.read_u64::<LittleEndian>().unwrap() as u64 },
                                _ => { panic!("oh my guiness") },
                            }
                            if val != $val[0] as u64 { skip = true }
                        }
                        ()
                    },
                    CLASS::BLOCK     => {
                        let read_size: u64 = match form {
                            DW_FORM_BLOCK1 => { rdr.read_u8().unwrap() as u64 },
                            DW_FORM_BLOCK2 => { rdr.read_u16::<LittleEndian>().unwrap() as u64 },
                            DW_FORM_BLOCK4 => { rdr.read_u32::<LittleEndian>().unwrap() as u64 },
                            DW_FORM_BLOCK => { rdr.read_leb128().unwrap() as u64 },
                            _ => { panic!("oh my guiness") },
                        };
                        if !skip && $attr == name {
                            let position = rdr.position() as usize;
                            let inner: Vec<u8> = rdr.get_ref()[position..(position + read_size as usize)].to_vec();
                            let other: Vec<u8> = $val.to_vec();
                            if &inner != &$val { skip = true }
                        }
                        ()
                    },
                    CLASS::CONSTANT  => {
                        let data: u64 = match form {
                            DW_FORM_DATA1 => { rdr.read_u8().unwrap() as u64 },
                            DW_FORM_DATA2 => { rdr.read_u16::<LittleEndian>().unwrap() as u64 },
                            DW_FORM_DATA4 => { rdr.read_u32::<LittleEndian>().unwrap() as u64 },
                            DW_FORM_DATA8 => { rdr.read_u64::<LittleEndian>().unwrap() as u64 },
                            DW_FORM_SDATA => { rdr.read_leb128().unwrap() as u64 },
                            DW_FORM_UDATA => { rdr.read_leb128().unwrap() as u64 },
                            _ => { panic!("oh my guiness") },
                        };
                        if !skip && $attr == name {
                            if data != ($val[0] as u64) { skip = true }
                        }
                        ()
                    },
                    CLASS::EXPRLOC   => {
                        let read_size = rdr.read_leb128().unwrap() as u64;
                        if !skip && $attr == name {
                            let position = rdr.position() as usize;
                            let inner: Vec<u8> = rdr.get_ref()[position..(position + read_size as usize)].to_vec();
                            let other: Vec<u8> = $val.to_vec();
                            if &inner != &$val { skip = true }
                        }
                        ()
                    },
                    CLASS::FLAG      => {
                        if !skip && $attr == name { unimplemented!() }
                    },
                    CLASS::REFERENCE => {
                        if !skip && $attr == name { unimplemented!() }
                    },
                    CLASS::STRING    => {
                        if !skip && $attr == name { unimplemented!() }
                    },
                    CLASS::UNKNOWN   => {
                        if !skip && $attr == name { unimplemented!() }
                    }
                }
                )*
            }
        }
        result
    }}
}