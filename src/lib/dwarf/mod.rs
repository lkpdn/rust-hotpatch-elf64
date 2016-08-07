extern crate ptrace;
use byteorder::{ReadBytesExt, LittleEndian};
use std::io::{self, Read, BufRead};
use std::mem;
use util::GenError;
use std::collections::VecDeque;

pub mod x86_64;
pub mod consts;
use self::consts::*;

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
        let mut last_decl_code = 0;
        while vc.len() > 13 { // code + tag + children = 13
            let decl = AbbrevDecl::from_slice(&vc);
            if decl.code < last_decl_code {
                break;
            } else {
                last_decl_code = decl.code;
            }
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
                    _ => { panic!("oh my guinness") },
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
                    _ => { panic!("oh my guinness") },
                }
            },
            CLASS::EXPRLOC => {
                let read_size = rdr.read_leb128().unwrap();
                let position = rdr.position();
                let new_position = position + read_size;
                rdr.set_position(new_position);
                let mut parser = ExpressionParser::new(
                    rdr.get_ref()[position as usize..new_position as usize].to_vec()
                );
                match parser.consume() {
                    Ok(v) => {
                        let ret = unsafe { mem::transmute::<u64, [u8; 8]>(v.data) };
                        Ok(ret.to_vec())
                    },
                    Err(e) => { Err(e) },
                }
            },
            CLASS::FLAG => {
                match self.form {
                    DW_FORM_FLAG => {
                        if rdr.read_u8().unwrap() as u8 == 0 { Ok(vec![0; 1]) }
                        else { Ok(vec![1; 1]) }
                    },
                    DW_FORM_FLAG_PRESENT => { Ok(vec![1; 1]) },
                    _ => { panic!("oh my guinness") },
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
                    _ => { panic!("oh my guinness") },
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

#[derive(Clone)]
pub struct StackItem {
    data: u64,
    signed: bool,
}

impl StackItem {
    pub fn get_data(&self) -> u64 { self.data }
}

pub struct ExpressionParser {
    reader: io::Cursor<Vec<u8>>,
    stack: VecDeque<StackItem>,
    pid: Option<i32>,
}

impl ExpressionParser {
    pub fn new(stream: Vec<u8>) -> ExpressionParser {
        let rdr = io::Cursor::new(stream);
        let stack: VecDeque<StackItem> = VecDeque::new();
        ExpressionParser {
            reader: rdr,
            stack: stack,
            pid: None
        }
    }
    pub fn set_stack(&mut self, stack: VecDeque<StackItem>) -> () {
        self.stack = stack;
    }
    pub fn set_pid(&mut self, pid: i32) -> () {
        self.pid = Some(pid);
    }
    pub fn consume(&mut self) -> Result<StackItem, GenError> {
        if self.reader.position() == self.reader.get_ref().len() as u64 {
            match self.stack.pop_front() {
                Some(v) => { return Ok(v) },
                None => { return Err(GenError::Plain(String::from("nothing on stack"))) },
            }
        }
        let val = self.reader.read_u8().unwrap();
        let op = DW_OP(val);
        match op {
            /* literal encodings */
            DW_OP(i) if (0x30..0x4f).contains(i) => {
                self.stack.push_front(StackItem {
                    data: (i - 0x30) as u64,
                    signed: false,
                });
            },
            DW_OP_ADDR => {
                self.stack.push_front(StackItem {
                    data: self.reader.read_u64::<LittleEndian>().unwrap(),
                    signed: false,
                });
            },
            DW_OP_CONST1U => {
                self.stack.push_front(StackItem {
                    data: self.reader.read_u8().unwrap() as u64,
                    signed: false,
                });
            },
            DW_OP_CONST2U => {
                self.stack.push_front(StackItem {
                    data: self.reader.read_u16::<LittleEndian>().unwrap() as u64,
                    signed: false,
                });
            },
            DW_OP_CONST4U => {
                self.stack.push_front(StackItem {
                    data: self.reader.read_u32::<LittleEndian>().unwrap() as u64,
                    signed: false,
                });
            },
            DW_OP_CONST8U => {
                self.stack.push_front(StackItem {
                    data: self.reader.read_u64::<LittleEndian>().unwrap(),
                    signed: false,
                });
            },
            DW_OP_CONST1S => {
                self.stack.push_front(StackItem {
                    data: self.reader.read_i8().unwrap() as u64,
                    signed: true,
                });
            },
            DW_OP_CONST2S => {
                self.stack.push_front(StackItem {
                    data: self.reader.read_i16::<LittleEndian>().unwrap() as u64,
                    signed: true,
                });
            },
            DW_OP_CONST4S => {
                self.stack.push_front(StackItem {
                    data: self.reader.read_i32::<LittleEndian>().unwrap() as u64,
                    signed: true,
                })
            },
            DW_OP_CONST8S => {
                self.stack.push_front(StackItem {
                    data: self.reader.read_i64::<LittleEndian>().unwrap() as u64,
                    signed: true,
                })
            },
            DW_OP_CONSTU => {
                self.stack.push_front(StackItem {
                    data: self.reader.read_leb128().unwrap() as u64,
                    signed: false,
                })
            },
            DW_OP_CONSTS => {
                self.stack.push_front(StackItem {
                    data: self.reader.read_leb128().unwrap() as u64,
                    signed: true,
                })
            },
            DW_OP_DUP => {
                let front = (*(self.stack.front().unwrap())).clone();
                self.stack.push_front(front);
            },
            DW_OP_DROP => {
                self.stack.pop_front();
            },
            DW_OP_PICK => {
                let index = self.reader.read_u8().unwrap() as usize;
                let copy = self.stack.get(index).unwrap().clone();
                self.stack.push_front(copy);
            },
            DW_OP_OVER => {
                let copy = self.stack.get(1).unwrap().clone();
                self.stack.push_front(copy);
            },
            DW_OP_SWAP => {
                self.stack.swap(0, 1);
            },
            DW_OP_ROT => {
                self.stack.swap(0, 2);
                self.stack.swap(0, 1);
            },
            DW_OP_DEREF => {
                let addr = self.stack.pop_front().unwrap().data as u64;
                try!(ptrace::attach(self.pid.unwrap())
                  .map_err(|e| GenError::RawOsError(e)));
                let reader = ptrace::Reader::new(self.pid.unwrap());
                match reader.peek_data(addr) {
                    Ok(v) => {
                        self.stack.push_front(StackItem {
                            data: v,
                            signed: false,
                        });
                    },
                    Err(_) => {
                        return Err(GenError::RawOsError(
                          io::Error::last_os_error().raw_os_error().unwrap() as usize)
                        );
                    }
                }
            },
            DW_OP_DEREF_SIZE => {
                let addr = self.stack.pop_front().unwrap().data as u64;
                try!(ptrace::attach(self.pid.unwrap())
                  .map_err(|e| GenError::RawOsError(e)));
                let reader = ptrace::Reader::new(self.pid.unwrap());
                match reader.peek_data(addr) {
                    Ok(v) => {
                        self.stack.push_front(StackItem {
                            data: {
                                let siz = self.reader.read_u8().unwrap();
                                (v << (8 - siz) as u64) >> (8 - siz)
                            },
                            signed: false,
                        });
                    },
                    Err(_) => {
                        return Err(GenError::RawOsError(
                          io::Error::last_os_error().raw_os_error().unwrap() as usize)
                        );
                    }
                }
            },
            DW_OP_CALL_FRAME_CFA => {},
            DW_OP_ABS => {
                let n = self.stack.pop_front().unwrap().data as i64;
                self.stack.push_front(StackItem {
                    data: n.abs() as u64,
                    signed: false,
                });
            },
            DW_OP_AND => {
                let n = self.stack.pop_front().unwrap().data;
                let m = self.stack.pop_front().unwrap().data;
                self.stack.push_front(StackItem {
                    data: n & m,
                    signed: false,
                });
            },
            DW_OP_DIV => {
                let n = self.stack.pop_front().unwrap().data as i64;
                let m = self.stack.pop_front().unwrap().data as i64;
                self.stack.push_front(StackItem {
                    data: (m / n) as u64,
                    signed: true,
                });
            },
            DW_OP_MINUS => {
                let n = self.stack.pop_front().unwrap().data as i64;
                let m = self.stack.pop_front().unwrap().data as i64;
                self.stack.push_front(StackItem {
                    data: (m - n) as u64,
                    signed: true,
                });
            },
            DW_OP_MOD => {
                let n = self.stack.pop_front().unwrap().data as i64;
                let m = self.stack.pop_front().unwrap().data as i64;
                self.stack.push_front(StackItem {
                    data: (m % n) as u64,
                    signed: true,
                });
            },
            DW_OP_MUL => {
                let n = self.stack.pop_front().unwrap().data as i64;
                let m = self.stack.pop_front().unwrap().data as i64;
                self.stack.push_front(StackItem {
                    data: (m * n) as u64,
                    signed: true,
                });
            },
            DW_OP_NEG => {
                let n = self.stack.pop_front().unwrap().data as i64;
                self.stack.push_front(StackItem {
                    data: (- n) as u64,
                    signed: false,
                });
            },
            DW_OP_NOT => {
                let n = self.stack.pop_front().unwrap().data;
                self.stack.push_front(StackItem {
                    data: !n,
                    signed: false,
                });
            },
            DW_OP_OR => {
                let n = self.stack.pop_front().unwrap().data;
                let m = self.stack.pop_front().unwrap().data;
                self.stack.push_front(StackItem {
                    data: n | m,
                    signed: false,
                });
            },
            DW_OP_PLUS => {
                let n = self.stack.pop_front().unwrap().data;
                let m = self.stack.pop_front().unwrap().data;
                self.stack.push_front(StackItem {
                    data: n + m,
                    signed: false,
                });
            },
            _ => { unimplemented!() },
        }
        self.consume()
    }
}

/*
 * Format and debugging information
 */
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DW_TAG(pub u32);

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DW_CHILDREN(pub u8);

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DW_AT(pub u16);

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DW_FORM(pub u16);

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
        $debug_abbrev:ident,
        { DW_TAG => $tag:path,
        $($attr:path => $val:expr),* },
        $attr_to_get:expr,
        $val_type:ty
    ) => {{
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::intrinsics;
        use std::mem;
        use std::io;
        // consume header
        let mut rdr = io::Cursor::new($data.clone());
        let mut results: Vec<$val_type> = Vec::new();

        loop {
            let offset = rdr.position();
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
                    rdr.set_position(offset);
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
            let abbrev_decls = AbbrevDecls::from_debug_abbrev(
                (&$debug_abbrev[
                  compilation_unit_header.debug_abbrev_offset as usize
                  ..
                  $debug_abbrev.len()
                ]).to_vec()
            );
            let mut candidates: Vec<$val_type> = Vec::new();
            let cycle_limit = offset + compilation_unit_header.unit_length +
              compilation_unit_header.dwarf_bit as u64 / 8;
            while rdr.position() < cycle_limit {
                let abbrev_number = rdr.read_leb128().unwrap();
                debug!("abbrev num.: {}", abbrev_number);
                if abbrev_number == 0 { continue }
                let abbrev_decl: &AbbrevDecl = abbrev_decls.search_by_code(abbrev_number).unwrap();
                let tag: DW_TAG = abbrev_decl.tag;
                let mut skip: bool = false;
                if tag != $tag { skip = true }
                for attr_spec in &abbrev_decl.attr_specs {
                    let name: DW_AT = attr_spec.name;
                    debug!("{:?}", name);
                    let spec_data =  attr_spec.consume(&mut rdr, compilation_unit_header);
                    if spec_data.is_err() { continue }
                    let data: Vec<u8> = spec_data.unwrap();
                    if $attr_to_get == name {
                        unsafe {
                            candidates.push(match intrinsics::type_name::<$val_type>() {
                                "u64" => { data.as_slice().read_u64::<LittleEndian>().unwrap() },
                                _ => { mem::transmute(data.as_ptr() as $val_type) },
                            });
                        }
                    }
                    $(
                    if !skip && $attr == name {
                        let mut copied = data.clone();
                        if copied.len() < 8 {
                            let mut appended = vec![0; 8 - copied.len()];
                            copied.append(&mut appended);
                        }
                        if copied.as_slice().read_u64::<LittleEndian>().unwrap() != $val {
                            skip = true
                        }
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
            if rdr.position() == rdr.get_ref().len() as u64 { break }
        }
        results
    }}
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::consts::*;

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

    #[test]
    fn test_expression_parse() {
        let mut parser = ExpressionParser::new(vec![
            DW_OP_DUP.0, DW_OP_DROP.0, DW_OP_PICK.0, 2,
            DW_OP_OVER.0, DW_OP_SWAP.0, DW_OP_ROT.0
        ]);
        parser.set_stack(vec![
            StackItem{data: 17, signed: false},
            StackItem{data: 29, signed: false},
            StackItem{data: 1000, signed: false}
        ].into_iter().collect());
        let ret = parser.consume().unwrap().data;
        assert_eq!(ret, 17);
    }
}
