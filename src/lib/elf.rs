extern crate elf;
extern crate libc;
extern crate ptrace;
use byteorder::{ByteOrder, LittleEndian};
use std::cell::Cell;
use std::fmt;
use std::mem;
use std::path::PathBuf;
use std::str::pattern::Pattern;
use self::elf::*;
use util::GenError;
use lib::dwarf::*;
use lib::dwarf::consts::*;

pub trait ElfFileExt {
    fn get_sec_rela(&self, sec_name: &str) -> Result<Vec<SecRelaEntry>, GenError>;
}

impl ElfFileExt for elf::File {
    fn get_sec_rela(&self, sec_name: &str) -> Result<Vec<SecRelaEntry>, GenError> {
        match sec_name {
            ".rela.dyn"|".rela.plt" => (),
            _ => { return Err(GenError::Plain(format!("invalid request: {}", sec_name))) },
        };
        let mut result: Vec<SecRelaEntry> = Vec::new();
        let sec_dynsym = self.get_section(".dynsym").unwrap();
        let dynsyms = try!(self.get_symbols(sec_dynsym)
          .map_err(|e| GenError::ElfParseError(e)));
        match self.get_section(sec_name) {
            Some(s) => {
                let mut data_slice = &(s.data)[..];
                for _ in 0..(s.shdr.size / s.shdr.entsize) {
                    let r_offset: u64 = read_u64!(self, data_slice).unwrap();
                    let r_info: u64 = read_u64!(self, data_slice).unwrap();
                    let _r_addend: u64 = read_u64!(self, data_slice).unwrap();
                    let r_sym: u32 = (r_info >> 32) as u32;
                    let ref st_name: String = dynsyms[r_sym as usize].name;
                    result.push(SecRelaEntry {
                        r_offset: r_offset,
                        st_name: st_name.clone(),
                        fixed: false,
                    });
                }
                Ok(result)
            },
            None => Ok(Vec::new()),
        }
    }
}

pub struct SecRelaEntry {
    pub r_offset: u64,
    pub st_name: String,
    pub fixed: bool,
}

pub struct Fixer {
    pub elf: elf::File,
    pub relas: Vec<SecRelaEntry>,
    pub canvas: Cell<*mut libc::c_void>,
    pub canvas_size: usize,
}

impl Fixer {
    pub fn all_fixed(&self) -> bool {
        !self.relas.iter().any(|r| r.fixed == false)
    }
    pub fn write(&self, pid: i32, alloc_addr: u64) -> Result<(), GenError> {
        // write
        let writer = ptrace::Writer::new(pid);
        let buf = unsafe {
            Vec::from_raw_parts(
                mem::transmute::<*mut libc::c_void, *mut u8>(self.canvas.get()),
                self.canvas_size as usize,
                self.canvas_size as usize
            )
        };
        writer.write_data(alloc_addr as u64, &buf)
          .map_err(|e| GenError::Plain(format!("Error: {:?}", e)))
    }
    pub fn new(ef_path: &str) -> Result<Fixer, GenError> {
        let ef = try!(elf::File::open_path(PathBuf::from(ef_path))
          .map_err(|e| GenError::ElfParseError(e)));
        let buf_size = ef.sections
          .iter()
          .filter(|s| s.shdr.flags.0 & (elf::types::SHF_WRITE.0 | elf::types::SHF_ALLOC.0) != 0)
          .map(|s| ((s.shdr.addr + s.shdr.size + s.shdr.addralign - 1) /
            s.shdr.addralign) * s.shdr.addralign)
          .max().unwrap() as usize;
        let canvas: *mut libc::c_void = unsafe { libc::malloc(buf_size) };
        let mut relas: Vec<SecRelaEntry> = Vec::new();
        relas.append(ef.get_sec_rela(".rela.dyn").unwrap().as_mut());
        relas.append(ef.get_sec_rela(".rela.plt").unwrap().as_mut());
        Ok(Fixer {
            elf: ef,
            relas: relas,
            canvas: Cell::new(canvas),
            canvas_size: buf_size,
        })
    }
    pub fn rebuild_and_map(&mut self, symbols: &Vec<SymbolIdent>)
      -> Result<(), GenError> {
        for entry in &self.relas {
            if entry.fixed { continue }
            let mut found: Vec<SymbolIdent> = Vec::new();
            for s in symbols {
                if entry.st_name == s.symbol.name.as_ref() as &str &&
                  s.symbol.bind == elf::types::STB_GLOBAL {
                    found.push(s.clone());
                } else if (entry.st_name.clone() + ".").is_prefix_of(s.symbol.name.as_ref()) &&
                  s.symbol.bind != elf::types::STB_GLOBAL {
                    found.push(s.clone());
                }
            }
            if found.len() == 0 {
                warn!("st_name:{} not found", entry.st_name);
                continue
            } else if found.len() > 1 {
                warn!("st_name:{} cannot be fixed", entry.st_name);
                continue
            }
            info!("found: {:?}", found.first().unwrap().symbol.name);
            info!("r_offset:0x{:0>16x}, st_name:{}", entry.r_offset, entry.st_name);
            use std::slice;
            let mut t = unsafe { slice::from_raw_parts_mut(
                mem::transmute::<*mut libc::c_void, *mut u8>(
                    self.canvas.get().offset(entry.r_offset as isize)
                ), 8
            ) };
            LittleEndian::write_u64(t,
                found.first().unwrap().offset +
                found.first().unwrap().symbol.value);
        }
        Ok(())
    }
    // XXX: too ugly interface.
    pub fn try_on_dwarf(&mut self, exec_path: &str, var_name: String, filename: String,
      offset: u64) -> Result<(), GenError> {
        let ef = elf::File::open_path(exec_path).unwrap();
        let debug_abbrev_data: Vec<u8> = ef.get_section(".debug_abbrev").unwrap().data.clone();
        let abbrev_decls = AbbrevDecls::from_debug_abbrev(debug_abbrev_data);
        let debug_line: Vec<u8> = ef.get_section(".debug_line").unwrap().data.clone();
        let file_name_table = FileNameTable::from_debug_line(debug_line);
        let debug_info: Vec<u8> = ef.get_section(".debug_info").unwrap().data.clone();
        for mut entry in &mut self.relas {
            if entry.fixed || entry.st_name != var_name {
                continue
            }
            let fname_entry = file_name_table.search_filename(filename.clone()).unwrap().entry;
            let result : Vec<u64> = search_debug_info!(debug_info, abbrev_decls, {
              DW_TAG => DW_TAG_VARIABLE,
              DW_AT_DECL_FILE => fname_entry as u64
            }, DW_AT_LOCATION, u64);
            if result.len() == 1 {
                let value = result[0];
                entry.fixed = true;
                use std::slice;
                let mut t = unsafe { slice::from_raw_parts_mut(
                    mem::transmute::<*mut libc::c_void, *mut u8>(
                        self.canvas.get().offset(entry.r_offset as isize)
                    ), 8
                ) };
                LittleEndian::write_u64(t, offset + value);
            }
        }
        Ok(())
    }
}

pub struct SymbolIdent {
    pub symbol: elf::types::Symbol,
    pub offset: u64,
}

impl Clone for SymbolIdent {
    fn clone(&self) -> Self {
        SymbolIdent {
            symbol: self.symbol.clone(),
            offset: self.offset,
        }
    }
}

impl fmt::Debug for SymbolIdent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} (offset: 0x{:x})", self.symbol, self.offset)
    }
}

impl SymbolIdent {
    #[allow(dead_code)]
    pub fn get_from(ef: &elf::File, offset: u64) -> Vec<SymbolIdent> {
        let symbols = match ef.get_section(".symtab") {
            Some(s) => ef.get_symbols(s).expect("Failed to get symbols of .symtab"),
            None => { warn!("Failed to get .symtab."); vec![] }
        };
        let dynsyms = match ef.get_section(".dynsym") {
            Some(s) => ef.get_symbols(s).expect("Failed to get symbols of .dynsym"),
            None => panic!("Failed to get .dynsym"),
        };
        let mut syms: Vec<SymbolIdent> = Vec::new();
        for s in &symbols {
            if s.shndx != 0 && s.shndx < 0xff {
                trace!("{} SectionName: {}", s, ef.sections[s.shndx as usize].shdr.name);
                syms.push(SymbolIdent {
                    symbol: s.clone(),
                    offset: offset,
                });
            }
        };
        for s in &dynsyms {
            if s.shndx != 0 && s.shndx < 0xff {
                trace!("{} SectionName: {}", s, ef.sections[s.shndx as usize].shdr.name);
                syms.push(SymbolIdent {
                    symbol: s.clone(),
                    offset: offset,
                });
            }
        };
        syms
    }
}
