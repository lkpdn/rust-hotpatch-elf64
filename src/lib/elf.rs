extern crate elf;
extern crate libc;
use byteorder::{ByteOrder, LittleEndian};
use std::fmt;
use std::mem;
use std::str::pattern::Pattern;
use self::elf::*;
use util::GenError;
use lib::dwarf::*;

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

pub struct Fixer<'a> {
    pub elf: &'a elf::File,
    pub relas: Vec<SecRelaEntry>,
}

impl <'a> Fixer<'a> {
    pub fn all_fixed(&self) -> bool {
        !self.relas.iter().any(|r| r.fixed == false)
    }
    pub fn from_elf(ef: &'a elf::File) -> Result<Fixer<'a>, GenError> {
        let mut relas: Vec<SecRelaEntry> = Vec::new();
        relas.append(ef.get_sec_rela(".rela.dyn").unwrap().as_mut());
        relas.append(ef.get_sec_rela(".rela.plt").unwrap().as_mut());
        Ok(Fixer {
            elf: &ef,
            relas: relas,
        })
    }
    pub fn rebuild_and_map(&mut self, symbols: &Vec<SymbolIdent>, canvas: *mut libc::c_void)
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
                    canvas.offset(entry.r_offset as isize)
                ), 8
            ) };
            LittleEndian::write_u64(t,
                found.first().unwrap().offset +
                found.first().unwrap().symbol.value);
        }
        Ok(())
    }
    pub fn try_on_dwarf(&mut self, filepath: String, var_name: String, filename: String)
      -> Result<(), GenError> {
        let ef = elf::File::open_path(&filepath).unwrap();
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
              DW_AT_DECL_FILE => &[fname_entry]
            }, DW_AT_LOCATION, u64);
            if result.len() == 1 {
                let _offset = result[0];
                entry.fixed = true;
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
