use byteorder::ReadBytesExt;
use std::io::{self, Read, BufRead};
use std::mem;
use util::GenError;

#[derive(Debug, Clone, Copy)]
pub struct CompilationUnitHeader {
    pub unit_length: u64,
    pub version: u16,
    pub debug_abbrev_offset: u64,
    pub address_size: u8,
    pub dwarf_bit: u8,
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
    pub fn search_by_code(&self, code: u64) -> Result<&AbbrevDecl, GenError> {
        self.decls.iter().by_ref()
          .find(|e| e.code == code)
          .ok_or(GenError::Plain(format!("AbbrevDecls: `code: {}` not found", code)))
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
        let code = consume_uleb128(&mut vc).unwrap();
        let tag = consume_uleb128(&mut vc).unwrap() as u32;
        let children = consume_uleb128(&mut vc).unwrap() as u8;
        let mut attr_specs: Vec<AbbrevDeclAttrSpec> = Vec::new();
        while vc.len() > 0 {
            let name = consume_uleb128(&mut vc).unwrap() as u16;
            let form = consume_uleb128(&mut vc).unwrap() as u16;
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

impl AbbrevDeclAttrSpec {
    pub fn consume(&self, rdr: &mut io::Cursor<Vec<u8>>, comp_unit_header: CompilationUnitHeader)
      -> Result<Vec<u8>, GenError> {
        match self.form.get_class() {
            CLASS::ADDRESS => {
                let mut buf = vec![0; comp_unit_header.address_size as usize];
                let _ = rdr.read(&mut buf);
                Ok(buf)
            },
            CLASS::BLOCK => {
                match self.form {
                    DW_FORM_BLOCK1 => {
                        let mut buf = vec![0; 1];
                        let _ = rdr.read(&mut buf);
                        Ok(buf)
                    },
                    DW_FORM_BLOCK2 => {
                        let mut buf = vec![0; 2];
                        let _ = rdr.read(&mut buf);
                        Ok(buf)
                    },
                    DW_FORM_BLOCK4 => {
                        let mut buf = vec![0; 4];
                        let _ = rdr.read(&mut buf);
                        Ok(buf)
                    },
                    DW_FORM_BLOCK => {
                        rdr.read_leb128_stream()
                    },
                    _ => { panic!("oh my guiness") },
                }
            },
            CLASS::CONSTANT  => {
                match self.form {
                    DW_FORM_DATA1 => {
                        let mut buf = vec![0; 1];
                        let _ = rdr.read(&mut buf);
                        Ok(buf)
                    },
                    DW_FORM_DATA2 => {
                        let mut buf = vec![0; 2];
                        let _ = rdr.read(&mut buf);
                        Ok(buf)
                    },
                    DW_FORM_DATA4 => {
                        let mut buf = vec![0; 4];
                        let _ = rdr.read(&mut buf);
                        Ok(buf)
                    },
                    DW_FORM_DATA8 => {
                        let mut buf = vec![0; 8];
                        let _ = rdr.read(&mut buf);
                        Ok(buf)
                    },
                    DW_FORM_SDATA => {
                        rdr.read_leb128_stream()
                    },
                    DW_FORM_UDATA => {
                        rdr.read_leb128_stream()
                    },
                    _ => { panic!("oh my guiness") },
                }
            },
            CLASS::EXPRLOC => {
                let read_size = rdr.read_leb128().unwrap();
                let op = rdr.read_u8().unwrap();
                let num_of_operands = DW_OP(op).num_of_operands();
                if num_of_operands == 0 {
                    return Ok(vec![op;1])
                }
                let position = rdr.position();
                let new_position = position + read_size - 1;
                rdr.set_position(new_position);
                Ok(rdr.get_ref()[position as usize..new_position as usize].to_vec())
            },
            CLASS::FLAG => {
                match self.form {
                    DW_FORM_FLAG => {
                        if rdr.read_u8().unwrap() as u8 == 0 { Ok(vec![0; 1]) }
                        else { Ok(vec![1; 1]) }
                    },
                    DW_FORM_FLAG_PRESENT => { Ok(vec![1; 1]) },
                    _ => { panic!("oh my guiness") },
                }
            },
            CLASS::REFERENCE => {
                match self.form {
                    DW_FORM_REF1 => {
                        let mut buf = vec![0; 1];
                        let _ = rdr.read(&mut buf);
                        Ok(buf)
                    },
                    DW_FORM_REF2 => {
                        let mut buf = vec![0; 2];
                        let _ = rdr.read(&mut buf);
                        Ok(buf)
                    },
                    DW_FORM_REF4 => {
                        let mut buf = vec![0; 4];
                        let _ = rdr.read(&mut buf);
                        Ok(buf)
                    },
                    DW_FORM_REF8 => {
                        let mut buf = vec![0; 8];
                        let _ = rdr.read(&mut buf);
                        Ok(buf)
                    },
                    DW_FORM_REF_UDATA => {
                        rdr.read_leb128_stream()
                    },
                    _ => { panic!("oh my guiness") },
                }
            },
            CLASS::STRING => {
                match self.form {
                    DW_FORM_STRING => {
                        let mut buf = Vec::new();
                        let _ = rdr.read_until(0, &mut buf);
                        Ok(buf)
                    },
                    DW_FORM_STRP => {
                        let mut buf = match comp_unit_header.dwarf_bit {
                            32u8 => { vec![0; 4] },
                            64u8 => { vec![0; 8] },
                            _ => { panic!("oh my guinness") },
                        };
                        let _ = rdr.read(&mut buf);
                        Ok(buf)
                    },
                    _ => { panic!("oh my guinness") },
                }
            },
            CLASS::V4PTRS => {
                let mut buf = match comp_unit_header.dwarf_bit {
                    32u8 => { vec![0; 4] },
                    64u8 => { vec![0; 8] },
                    _ => { panic!("oh my guinness") },
                };
                let _ = rdr.read(&mut buf);
                Ok(buf)
            },
            CLASS::UNKNOWN => {
                unimplemented!()
            }
        }
    }
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
        let (sol_offset, opcode_base) = match &debug_line[0..4] {
            // unit_length(12/4) + version(2/2) + header_length(8/4)
            // + minimum_instruction_length(1/1)
            // + default_is_stmt(1/1) + line_base(1/1) + line_range(1/1)
            // + opcode_base(1/1) + standard_opcode_lengths(LEB128 × (opcode_base -1))
            // + include_directories(sequence of null-terminated strings)
            &[0xff, 0xff, 0xff, 0xff] => {
                (12 + 2 + 8 + 1 + 1 + 1 + 1 + 1, debug_line[26])
            },
            _ => {
                (4 + 2 + 4 + 1 + 1 + 1 + 1 + 1, debug_line[14])
            }
        };
        let mut pile = debug_line.clone();

        // standard_opcode_lengths(LEB128 × (opcode_base -1))
        pile.drain(0..sol_offset);
        for _ in 0..(opcode_base - 1) {
            let _ = consume_uleb128(&mut pile);
        }
        if pile[0] == 0x00 { // Directory table empty
            pile.remove(0);
        } else {
            let filenames_offset = pile.windows(2)
              .position(|w| w[0] == 0x00 && w[1] == 0x00)
              .unwrap() + 2;
            pile.drain(0..filenames_offset);
        }
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
            let dir = consume_uleb128(&mut vc).unwrap() as u8;
            let time = consume_uleb128(&mut vc).unwrap() as u8;
            let size = consume_uleb128(&mut vc).unwrap() as u8;
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
    pub fn search_filename(&self, filename: String) -> Result<&FileNameTableEntry, GenError> {
        self.entries.iter().by_ref()
          .find(|e| e.name == filename)
          .ok_or(GenError::Plain(format!("FileNameTable.search_filename: `name: {}` not found", filename)))
    }
}

/*
 * Format and debugging information
 */
#[allow(non_camel_case_types)]
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

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DW_CHILDREN(pub u8);
pub const DW_CHILDREN_NO : DW_CHILDREN = DW_CHILDREN(0x00);
pub const DW_CHILDREN_YES : DW_CHILDREN = DW_CHILDREN(0x01);

#[allow(non_camel_case_types)]
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

#[allow(non_camel_case_types)]
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
            DW_FORM_SEC_OFFSET => CLASS::V4PTRS,
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
    V4PTRS,
    UNKNOWN,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DW_OP(pub u8);
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

impl DW_OP {
    fn num_of_operands(&self) -> u8 {
        match *self {
            DW_OP_ADDR => 1,
            DW_OP_DEREF => 0,
            DW_OP_CONST1U => 1,
            DW_OP_CONST1S => 1,
            DW_OP_CONST2U => 1,
            DW_OP_CONST2S => 1,
            DW_OP_CONST4U => 1,
            DW_OP_CONST4S => 1,
            DW_OP_CONST8U => 1,
            DW_OP_CONST8S => 1,
            DW_OP_CONSTU => 1,
            DW_OP_CONSTS => 1,
            DW_OP_DUP => 0,
            DW_OP_DROP => 0,
            DW_OP_OVER => 0,
            DW_OP_PICK => 1,
            DW_OP_SWAP => 0,
            DW_OP_ROT => 0,
            DW_OP_XDEREF => 0,
            DW_OP_ABS => 0,
            DW_OP_AND => 0,
            DW_OP_DIV => 0,
            DW_OP_MINUS => 0,
            DW_OP_MOD => 0,
            DW_OP_MUL => 0,
            DW_OP_NEG => 0,
            DW_OP_NOT => 0,
            DW_OP_OR => 0,
            DW_OP_PLUS => 0,
            DW_OP_PLUS_UCONST => 1,
            DW_OP_SHL => 0,
            DW_OP_SHR => 0,
            DW_OP_SHRA => 0,
            DW_OP_XOR => 0,
            DW_OP_SKIP => 1,
            DW_OP_BRA => 1,
            DW_OP_EQ => 0,
            DW_OP_GE => 0,
            DW_OP_GT => 0,
            DW_OP_LE => 0,
            DW_OP_LT => 0,
            DW_OP_NE => 0,
            DW_OP_LIT0 => 0,
            DW_OP_LIT1 => 0,
            DW_OP_LIT2 => 0,
            DW_OP_LIT3 => 0,
            DW_OP_LIT4 => 0,
            DW_OP_LIT5 => 0,
            DW_OP_LIT6 => 0,
            DW_OP_LIT7 => 0,
            DW_OP_LIT8 => 0,
            DW_OP_LIT9 => 0,
            DW_OP_LIT10 => 0,
            DW_OP_LIT11 => 0,
            DW_OP_LIT12 => 0,
            DW_OP_LIT13 => 0,
            DW_OP_LIT14 => 0,
            DW_OP_LIT15 => 0,
            DW_OP_LIT16 => 0,
            DW_OP_LIT17 => 0,
            DW_OP_LIT18 => 0,
            DW_OP_LIT19 => 0,
            DW_OP_LIT20 => 0,
            DW_OP_LIT21 => 0,
            DW_OP_LIT22 => 0,
            DW_OP_LIT23 => 0,
            DW_OP_LIT24 => 0,
            DW_OP_LIT25 => 0,
            DW_OP_LIT26 => 0,
            DW_OP_LIT27 => 0,
            DW_OP_LIT28 => 0,
            DW_OP_LIT29 => 0,
            DW_OP_LIT30 => 0,
            DW_OP_LIT31 => 0,
            DW_OP_REG0 => 0,
            DW_OP_REG1 => 0,
            DW_OP_REG2 => 0,
            DW_OP_REG3 => 0,
            DW_OP_REG4 => 0,
            DW_OP_REG5 => 0,
            DW_OP_REG6 => 0,
            DW_OP_REG7 => 0,
            DW_OP_REG8 => 0,
            DW_OP_REG9 => 0,
            DW_OP_REG10 => 0,
            DW_OP_REG11 => 0,
            DW_OP_REG12 => 0,
            DW_OP_REG13 => 0,
            DW_OP_REG14 => 0,
            DW_OP_REG15 => 0,
            DW_OP_REG16 => 0,
            DW_OP_REG17 => 0,
            DW_OP_REG18 => 0,
            DW_OP_REG19 => 0,
            DW_OP_REG20 => 0,
            DW_OP_REG21 => 0,
            DW_OP_REG22 => 0,
            DW_OP_REG23 => 0,
            DW_OP_REG24 => 0,
            DW_OP_REG25 => 0,
            DW_OP_REG26 => 0,
            DW_OP_REG27 => 0,
            DW_OP_REG28 => 0,
            DW_OP_REG29 => 0,
            DW_OP_REG30 => 0,
            DW_OP_REG31 => 0,
            DW_OP_BREG0 => 1,
            DW_OP_BREG1 => 1,
            DW_OP_BREG2 => 1,
            DW_OP_BREG3 => 1,
            DW_OP_BREG4 => 1,
            DW_OP_BREG5 => 1,
            DW_OP_BREG6 => 1,
            DW_OP_BREG7 => 1,
            DW_OP_BREG8 => 1,
            DW_OP_BREG9 => 1,
            DW_OP_BREG10 => 1,
            DW_OP_BREG11 => 1,
            DW_OP_BREG12 => 1,
            DW_OP_BREG13 => 1,
            DW_OP_BREG14 => 1,
            DW_OP_BREG15 => 1,
            DW_OP_BREG16 => 1,
            DW_OP_BREG17 => 1,
            DW_OP_BREG18 => 1,
            DW_OP_BREG19 => 1,
            DW_OP_BREG20 => 1,
            DW_OP_BREG21 => 1,
            DW_OP_BREG22 => 1,
            DW_OP_BREG23 => 1,
            DW_OP_BREG24 => 1,
            DW_OP_BREG25 => 1,
            DW_OP_BREG26 => 1,
            DW_OP_BREG27 => 1,
            DW_OP_BREG28 => 1,
            DW_OP_BREG29 => 1,
            DW_OP_BREG30 => 1,
            DW_OP_BREG31 => 1,
            DW_OP_REGX => 1,
            DW_OP_FBREG => 1,
            DW_OP_BREGX => 2,
            DW_OP_PIECE => 1,
            DW_OP_DEREF_SIZE => 1,
            DW_OP_XDEREF_SIZE => 1,
            DW_OP_NOP => 0,
            DW_OP_PUSH_OBJECT_ADDRESS => 0,
            DW_OP_CALL2 => 1,
            DW_OP_CALL4 => 1,
            DW_OP_CALL_REF => 1,
            DW_OP_FORM_TLS_ADDRESS => 0,
            DW_OP_CALL_FRAME_CFA => 0,
            DW_OP_BIT_PIECE => 2,
            DW_OP_IMPLICIT_VALUE => 2,
            DW_OP_STACK_VALUE => 0,
            DW_OP_LO_USER => 0,
            DW_OP_HI_USER => 0,
            DW_OP(_) => { panic!("oh my guinness") },
        }
    }
}

pub fn consume_uleb128(v: &mut Vec<u8>) -> Result<u64, GenError> {
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

pub fn consume_sleb128(v: &mut Vec<u8>) -> Result<i64, GenError> {
    let mut buf: Vec<u8> = vec![];
    loop {
        let read = v.remove(0);
        buf.push(read);
        if read & 0b1000_0000 == 0 { break }
    }
    let mut res: i64 = 0;
    let mut shift = 0;
    for b in &buf {
        res |= ((b & 0b0111_1111) as i64) << shift;
        shift += 7;
        if b & 0b1000_0000 == 0 { break }
    }
    if (1 << (shift - 1)) & res != 0 {
        res |= (-1 as i64) << shift;
    }
    Ok(res)
}

pub fn consume_uleb128_stream(v: &mut Vec<u8>) -> Result<Vec<u8>, GenError> {
    let res: u64 = consume_uleb128(v).unwrap();
    unsafe { Ok(mem::transmute::<u64, [u8;8]>(res).as_ref().to_vec()) }
}

pub trait CursorExt {
    fn read_leb128(&mut self) -> Result<u64, GenError>;
    fn read_leb128_stream(&mut self) -> Result<Vec<u8>, GenError>;
}

impl CursorExt for io::Cursor<Vec<u8>> {
    fn read_leb128(&mut self) -> Result<u64, GenError> {
        // XXX: avoid inefficient cloning
        let position = self.position();
        let mut v: Vec<u8> = self.get_ref().clone();
        v.drain(0..position as usize);
        let mut size = v.len() as u64;
        let result = consume_uleb128(&mut v).unwrap();
        size -= v.len() as u64;
        self.set_position(position + size);
        Ok(result)
    }
    fn read_leb128_stream(&mut self) -> Result<Vec<u8>, GenError> {
        // XXX: avoid inefficient cloning
        let position = self.position();
        let mut v: Vec<u8> = self.get_ref().clone();
        v.drain(0..position as usize);
        let mut size = v.len() as u64;
        let result = consume_uleb128_stream(&mut v).unwrap();
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
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::intrinsics;
        use std::mem;
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
                    dwarf_bit: 64u8,
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
                    dwarf_bit: 32u8,
                }
            }
        };

        // XXX: avoid inefficient loop and match
        let mut results: Vec<$val_type> = Vec::new();
        let mut candidates: Vec<$val_type> = Vec::new();
        loop {
            let abbrev_number = rdr.read_leb128().unwrap();
            if rdr.position() == rdr.get_ref().len() as u64 { break }
            if abbrev_number == 0 { continue }
            let abbrev_decl: &AbbrevDecl = $abbrev_decls.search_by_code(abbrev_number).unwrap();
            let tag: DW_TAG = abbrev_decl.tag;
            let mut skip: bool = false;
            if tag != $tag { skip = true }
            for attr_spec in &abbrev_decl.attr_specs {
                let name: DW_AT = attr_spec.name;
                $(
                let data: Vec<u8> = attr_spec.consume(&mut rdr, compilation_unit_header).unwrap();
                if $attr_to_get == name {
                    unsafe {
                        candidates.push(match intrinsics::type_name::<$val_type>() {
                            "u64" => { data.as_slice().read_u64::<LittleEndian>().unwrap() },
                            _ => { mem::transmute(data.as_ptr() as $val_type) },
                        });
                    }
                }
                if !skip && $attr == name {
                    if ! data.starts_with($val) { skip = true }
                }
                )*
            }
            if skip == false {
                match candidates.pop() {
                    Some(c) => results.push(c),
                    None => (),
                }
            }
        }
        results
    }}
}

#[cfg(test)]
mod tests {
    use super::{consume_uleb128,consume_sleb128};

    #[test]
    fn test_consume_uleb128() {
        assert_eq!(consume_uleb128(&mut vec![0x2u8]).unwrap(), 2);
        assert_eq!(consume_uleb128(&mut vec![0x7f]).unwrap(), 127);
        assert_eq!(consume_uleb128(&mut vec![0x80, 0x01]).unwrap(), 128);
        assert_eq!(consume_uleb128(&mut vec![0x81, 0x01]).unwrap(), 129);
        assert_eq!(consume_uleb128(&mut vec![0x82, 0x01]).unwrap(), 130);
        assert_eq!(consume_uleb128(&mut vec![0xb9, 0x64]).unwrap(), 12857);
    }

    #[test]
    fn test_consume_sleb128() {
        assert_eq!(consume_sleb128(&mut vec![0x02]).unwrap(), 2);
        assert_eq!(consume_sleb128(&mut vec![0x7e]).unwrap(), -2);
        assert_eq!(consume_sleb128(&mut vec![0xff, 0x00]).unwrap(), 127);
        assert_eq!(consume_sleb128(&mut vec![0x81, 0x7f]).unwrap(), -127);
        assert_eq!(consume_sleb128(&mut vec![0x80, 0x01]).unwrap(), 128);
        assert_eq!(consume_sleb128(&mut vec![0x80, 0x7f]).unwrap(), -128);
        assert_eq!(consume_sleb128(&mut vec![0x81, 0x01]).unwrap(), 129);
        assert_eq!(consume_sleb128(&mut vec![0xff, 0x7e]).unwrap(), -129);
    }
}
