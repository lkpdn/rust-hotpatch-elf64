extern crate elf;
extern crate libc;
use byteorder::{ByteOrder, LittleEndian};
use std::fmt;
use std::mem;
use std::str::pattern::Pattern;
use self::elf::*;
use util::GenError;

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

macro_rules! map_it { (
    $rela_sec:expr,
    $symbols:ident,
    $canvas:ident
) => {
    for entry in $rela_sec {
        if entry.fixed { continue }
        let mut found: Vec<SymbolIdent> = Vec::new();
        for s in $symbols {
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
                $canvas.offset(entry.r_offset as isize)
            ), 8
        ) };
        LittleEndian::write_u64(t,
            found.first().unwrap().offset +
            found.first().unwrap().symbol.value);
    }
}}

pub struct Fixer<'a> {
    pub elf: &'a elf::File,
    pub rela_dyns: Vec<SecRelaEntry>,
    pub rela_plts: Vec<SecRelaEntry>,
}

impl <'a> Fixer<'a> {
    fn from_elf(ef: &'a elf::File) -> Result<Fixer<'a>, GenError> {
        let sec_dynsym = ef.get_section(".dynsym").unwrap();
        let dynsyms = try!(ef.get_symbols(sec_dynsym)
          .map_err(|e| GenError::ElfParseError(e)));
        let rela_dyns: Vec<SecRelaEntry> = ef.get_sec_rela(".rela.dyn").unwrap();
        let rela_plts: Vec<SecRelaEntry> = ef.get_sec_rela(".rela.plt").unwrap();
        Ok(Fixer {
            elf: &ef,
            rela_dyns: rela_dyns,
            rela_plts: rela_plts,
        })
    }
    fn rebuild_and_map(&mut self, symbols: &Vec<SymbolIdent>, canvas: *mut libc::c_void)
      -> Result<(), GenError> {
        map_it!(&self.rela_dyns, symbols, canvas);
        map_it!(&self.rela_plts, symbols, canvas);
        Ok(())
    }
    fn try_on_dwarf(&self) -> Result<(), GenError> {
        Ok(())
    }
}

struct SymbolIdent {
    symbol: elf::types::Symbol,
    offset: u64,
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
    fn get_from(ef: &elf::File, offset: u64) -> Vec<SymbolIdent> {
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
