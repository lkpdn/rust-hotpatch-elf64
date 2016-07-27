extern crate elf;
extern crate regex;
extern crate libc;
extern crate byteorder;
extern crate posix_ipc as ipc;
use std::mem;
use std::ptr;
use std::io;
use ptrace_ext::ptrace;

use ::dwarf::*;

macro_rules! map_it {
    (
        $elf:ident,
        $section:expr,
        $dynsyms:ident,
        $symbol_idents:expr,
        $canvas:ident
    ) => {
        match $elf.get_section($section) {
            Some(s) => {
                let mut data_slice = &(s.data)[..];
                for _ in 0..(s.shdr.size / s.shdr.entsize) {
                    let r_offset: u64 = read_u64!($elf, data_slice).unwrap();
                    let r_info: u64 = read_u64!($elf, data_slice).unwrap();
                    let _r_addend: u64 = read_u64!($elf, data_slice).unwrap();
                    let r_sym: u32 = (r_info >> 32) as u32;
                    let ref st_name: String = $dynsyms[r_sym as usize].name;
                    use std::str::pattern::Pattern;
                    let mut found: Vec<SymbolIdent> = Vec::new();
                    // XXX: decode locally static one's UUID if necessary, in gcc case.
                    for s in $symbol_idents {
                        if found.len() > 0 &&
                           found.first().unwrap().symbol.bind == elf::types::STB_GLOBAL {
                            continue;
                        }
                        if st_name == s.symbol.name.as_ref() as &str {
                            if s.symbol.bind == elf::types::STB_GLOBAL {
                                found = vec![s.clone()];
                            }
                        } else if (st_name.clone() + ".").is_prefix_of(s.symbol.name.as_ref()) {
                            if s.symbol.bind != elf::types::STB_GLOBAL {
                                found = vec![s.clone()];
                            }
                        }
                    }
                    if found.len() == 0 {
                        warn!("st_name:{} not found!", st_name);
                        continue;
                    }
                    info!("found: {:?}", found.first().unwrap().symbol.name);
                    info!("r_offset:0x{:0>16x}, st_name:{}", r_offset, st_name);
                    use std::slice;
                    let mut t = slice::from_raw_parts_mut(
                        mem::transmute::<*mut libc::c_void, *mut u8>(
                            $canvas.offset(r_offset as isize)
                        ), 8
                    );
                    LittleEndian::write_u64(t,
                        found.first().unwrap().offset +
                        found.first().unwrap().symbol.value);
                }
            },
            None => (),
        }
    };
}

pub fn set_data(pid:i32, addr: u64, buf: Vec<u8>, size: usize) -> Result<(), ::GenError> {
    let writer = ptrace::Writer::new(pid);
    info!("set_data(addr:{}, size:{})", addr, size);
    writer.write_data(addr as u64, &buf)
      .map_err(|e| ::GenError::RawOsError(e))
}

pub fn dump_canvas<T: io::Write>(canvas: *mut libc::c_void, buf_size: usize, writer: &mut T) {
    let mut buffer: Vec<u8> = Vec::new();
    let mut line_start: usize = 0;
    let mut last_line_zeros: bool = false;
    for i in 0...buf_size {
        if buffer.len() == 32 || i == buf_size {
            match buffer
              .iter()
              .fold(0, |acc, &x| {
                  if x > 0 { acc + 1}
                  else { acc }
              }) {
                0 => {
                    if last_line_zeros == false {
                        writeln!(writer, "{}", ":");
                    }
                    last_line_zeros = true;
                },
                _ => {
                    last_line_zeros = false;
                    write!(writer, "0x{:0>16x}:", line_start);
                    for j in 0..buffer.len() {
                        if j % 8 == 0 { write!(writer, "{}", " "); }
                        else if j % 4 == 0 { write!(writer, "{}", "_"); }
                        write!(writer, "{:0>2x}", buffer[j]);
                    }
                    writeln!(writer, "");
                }
            }
        }
        if buffer.len() == 32 {
            line_start = i;
            buffer.drain(..);
        }
        if i == buf_size { break }
        unsafe {
            let read_byte = ptr::read_volatile(
                mem::transmute::<*mut libc::c_void, *mut u8>(
                    canvas.offset(i as isize)
                )
            );
            buffer.push(read_byte);
        }
    }
}

pub fn try_on_dwarf(filepath: String, var_name: String, filename: String)
  -> Result<u64, ::GenError> {
    let ef = elf::File::open_path(&filepath).unwrap();
    let debug_abbrev_data: Vec<u8> = ef.get_section(".debug_abbrev").unwrap().data.clone();
    let abbrev_decls = AbbrevDecls::from_debug_abbrev(debug_abbrev_data);
    let debug_line: Vec<u8> = ef.get_section(".debug_line").unwrap().data.clone();
    let file_name_table = FileNameTable::from_debug_line(debug_line);
    let fname_entry = file_name_table.search_filename(filename).unwrap().entry;
    let debug_info: Vec<u8> = ef.get_section(".debug_info").unwrap().data.clone();
    let result : Vec<u64> = search_debug_info!(debug_info, abbrev_decls, {
      DW_TAG => DW_TAG_VARIABLE,
      DW_AT_DECL_FILE => &[fname_entry]
    }, DW_AT_LOCATION, u64);
    if result.len() > 1 { Err(::GenError::Plain("cannot choose appropriate one".to_string())) }
    else if result.len() == 1 { Ok(result[0]) }
    else { Err(::GenError::Plain("it was a fruitless try".to_string())) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc;
    use std::ptr::copy_nonoverlapping;
    use std::ffi::CString;
    use std::process::Command;

    #[test]
    fn test_dump_canvas() {
        let data = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
        ];
        let mut w: Vec<u8> = vec![0; data.len()];
        unsafe {
            let canvas: *mut libc::c_void = libc::malloc(data.len());
            let buf = CString::from_vec_unchecked(data.clone());
            let buf_addr: *mut libc::c_void = buf.as_ptr() as *mut libc::c_void;
            copy_nonoverlapping(buf_addr, canvas, data.len());
            dump_canvas(canvas, data.len(), &mut w);
            libc::free(canvas);
        }
        assert_eq!(w[227..232], [10, 58, 10, 48, 120]);
    }

    #[test]
    fn test_try_on_dwarf() {
        //let filepath = String::from("./files/c/test1");
        let filepath = String::from("./files/c/build/test1");
        let var_name = String::from("s_buf");
        let filename = String::from("test1.c");
        Command::new("/usr/bin/make")
          .current_dir("./files/c")
          .arg("all")
          .status()
          .expect("failed to make");
        try_on_dwarf(filepath, var_name, filename);
    }
}
