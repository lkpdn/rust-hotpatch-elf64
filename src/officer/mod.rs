extern crate elf;
extern crate regex;
extern crate libc;
extern crate posix_ipc as ipc;
extern crate ptrace;
use log::LogLevel;
use regex::Regex;
use std::path::{Path, PathBuf};
use std::io::BufReader;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::mem;
use std::time::Duration;
use std::ptr;
use std::thread;
use lib::ptrace::*;
use lib::elf::{Fixer, SymbolIdent};

use util::GenError;
#[macro_use]
pub mod helper;
use self::helper::*;

pub struct Officer {
    target: Target,
    parasites: Vec<Parasite>,
    fixer: Option<Box<Fixer>>,
}

impl Officer {
    pub fn add_parasite(&mut self, path: String, label: String) -> usize {
        match self.parasites.iter().position(|p| p.label == label) {
            Some(p) => {
                info!("duplicate label {} found", label);
                p
            },
            None => {
                let mut parasite = Parasite::new(self.target.pid);
                parasite.filepath = path;
                parasite.label = label;
                self.parasites.push(parasite);
                self.parasites.len() - 1
            }
        }
    }
    pub fn new(pid: i32, path: &Path) -> Result<Officer, GenError> {
        let mut target = Target {
            pid: pid,
            exec_path: path.to_path_buf(),
            offset: 0,
            symbols: vec![],
        };
        let maps =try!(fs::File::open(format!("/proc/{}/maps", &target.pid))
          .map_err(|e| GenError::StdIoError(e)));
        let mut br = BufReader::new(maps);
        let mut buffer = String::new();
        let mut read_ones = Vec::new();
        while br.read_line(&mut buffer).unwrap() > 0 {
            debug!("{:?}", buffer);
            let re = Regex::new(r"(?x)^
              (?P<addr_s>[:xdigit:]{1,16})
              -
              (?P<addr_e>[:xdigit:]{1,16})
              [:space:]
              (?P<perms>[rwxps-]{4})
              [:space:]
              (?P<offset>\d+)
              [:space:]
              (?P<dev>[:xdigit:]{2}:[:xdigit:]{2})
              [:space:]
              (?P<inode>\d+)
              [:space:]+
              (?P<pathname>\S+)
            ").unwrap();
            for cap in re.captures_iter(&*buffer) {
                let addr_s = u64::from_str_radix(cap.name("addr_s").unwrap(), 16).unwrap();
                let perms = cap.name("perms").unwrap() as &str;
                let offset = u64::from_str_radix(cap.name("offset").unwrap(), 10).unwrap();
                let path = PathBuf::from(cap.name("pathname").unwrap_or(""));
                // XXX:
                if perms.as_bytes()[0] != b'r' ||
                   perms.as_bytes()[2] != b'x' ||
                   offset > 0 {
                    continue
                }
                match elf::File::open_path(&path) {
                    Ok(f) => {
                        if read_ones.contains(&path) { continue }
                        if path == target.exec_path {
                            target.offset = addr_s;
                        }
                        read_ones.push(path.clone());
                        info!("get symbols from: {:?}", path);
                        target.symbols.append(SymbolIdent::get_from(&f, addr_s).as_mut());
                    },
                    Err(_) => ()
                };
            }
            buffer.clear();
        }
        Ok(Officer {
            target: target,
            parasites: vec![],
            fixer: None,
        })
    }
    pub fn attach_target(&self) -> Result<i64, GenError> {
        ptrace::attach(self.target.pid)
          .map_err(|e| GenError::RawOsError(e))
    }
    pub fn release_target(&self) -> Result<i64, GenError> {
        ptrace::release(self.target.pid, ipc::signals::Signal::None)
          .map_err(|e| GenError::RawOsError(e))
    }
    pub fn put_on_trampoline(&mut self, orig_func: String, label: String, new_func: String)
      -> Result<(), GenError> {
        let parasite = try!(self.parasites.iter().by_ref()
          .find(|p| p.label == label)
          .ok_or(GenError::Plain(format!("`{}` not loaded", label)))
        );
        let orig_func_symbol = try!(self.target.symbols.iter().by_ref()
          .find(|s| s.symbol.name == orig_func)
          .ok_or(GenError::Plain(format!("`{}` not found in target", orig_func)))
        );
        let gap_to_next = self.target.symbols.iter().by_ref().fold(::std::u64::MAX, |acc, x| {
            if x.symbol.value <= orig_func_symbol.symbol.value { return acc }
            let gap: u64 = x.symbol.value - orig_func_symbol.symbol.value;
            if gap < acc { return gap }
            acc
        }) as usize;
        let new_func_symbol = try!(parasite.symbols.iter().by_ref()
          .find(|s| s.symbol.name == new_func)
          .ok_or(GenError::Plain(format!("`{}` not found in {}", new_func, label)))
        );
        let new_func_addr = unsafe {
            mem::transmute::<u64, [u8; 8]>(
                new_func_symbol.symbol.value + new_func_symbol.offset
            )
        };
        let mut code = Vec::new();
        code.extend([0x48, 0xb8].iter().cloned());
        code.extend(new_func_addr.iter().cloned());
        code.extend(vec![0x90; gap_to_next - 14].iter().cloned());
        code.extend([0xff, 0xe0, 0xc9, 0xc3].iter().cloned());
        for c in code.iter() { debug!("0x{:0>2x}", c); }
        loop {
            match check_range_contains_rip(
              self.target.pid,
              (
                orig_func_symbol.symbol.value as u64
                ..
                (orig_func_symbol.symbol.value + gap_to_next as u64)
              )
            ).unwrap() {
                true => {
                    let _ = self.release_target();
                    thread::sleep(Duration::from_millis(20));
                    let _ = self.attach_target();
                },
                false => { break }
            }
        }
        try!(set_data(self.target.pid, orig_func_symbol.symbol.value, code.clone(), code.len()));
        Ok(())
    }
    pub fn dl(&mut self, idx: usize) -> Result<(), GenError> {
        let parasite = &mut self.parasites[idx];
        let mut fixer = Box::new(Fixer::new(&parasite.filepath).unwrap());
        // SHF_WRITE, SHF_ALLOC ONLY
        unsafe {
            let _ = fixer.elf.sections
              .iter()
              .filter(|s| s.shdr.flags.0 & (elf::types::SHF_WRITE.0 | elf::types::SHF_ALLOC.0) != 0)
              .map(|sec| {
                info!("{}: addr:{} offset:{} size:{} addralign:{}",
                    sec.shdr.name,
                    sec.shdr.addr,
                    sec.shdr.offset,
                    sec.shdr.size,
                    sec.shdr.addralign);
                ptr::copy_nonoverlapping(
                    sec.data.as_ptr() as *const libc::c_void,
                    fixer.canvas.get().offset(sec.shdr.addr as isize),
                    sec.shdr.size as usize
                );
              });

            if log_enabled!(LogLevel::Trace) {
                dump_canvas(fixer.canvas.get(), fixer.canvas_size as usize, &mut io::stdout());
            }

            fixer.rebuild_and_map(&self.target.symbols).unwrap();

            // alloc space in target virtual memory
            let alloc_addr = try!(parasite.target_alloc(fixer.canvas_size as u64));
            info!("will reside at 0x{:0>16x}", alloc_addr);

            // locally resolve symbols
            let mut so_symbols: Vec<SymbolIdent> = Vec::new();
            so_symbols.append(SymbolIdent::get_from(&(fixer.elf), alloc_addr).as_mut());
            for s in &so_symbols { print!("{} ", s.symbol.name); }

            fixer.rebuild_and_map(&so_symbols).unwrap();

            if log_enabled!(LogLevel::Trace) {
                dump_canvas(fixer.canvas.get(), fixer.canvas_size as usize, &mut io::stdout());
            }

            if ! fixer.all_fixed() {
                self.fixer = Some(fixer);
                return Err(GenError::Plain(String::from("Not all would be fixed up.")));
            }

            // write
            try!(fixer.write(self.target.pid, alloc_addr));

            parasite.addr = alloc_addr;
            parasite.symbols = so_symbols;
            self.fixer = Some(fixer);
        }
        Ok(())
    }
    pub fn fix_var(&mut self, var_name: String, source: String)
      -> Result<(), GenError> {
        let exec_path = self.target.exec_path.to_str().unwrap();
        let offset = self.target.offset;
        try!(self.fixer.as_mut()
          .ok_or(GenError::Plain(String::from("No fixer available")))
          .and_then(|f| {
              let _ = (*f).try_on_dwarf(String::from(exec_path), var_name, source, offset);
              Ok(())
          }));
        Ok(())
    }
}

struct Target {
    pid: i32,
    exec_path: PathBuf,
    offset: u64,
    symbols: Vec<SymbolIdent>,
}

struct Parasite {
    label: String,
    filepath: String,
    addr: u64,
    target_pid: i32,
    symbols: Vec<SymbolIdent>,
}

impl Parasite {
    fn new(pid: i32) -> Parasite {
        Parasite {
            label: String::new(),
            filepath: String::new(),
            addr: 0,
            target_pid: pid,
            symbols: vec![],
        }
    }
    fn target_alloc(&self, siz: u64) -> Result<u64, GenError> {
        let syscall = ptrace::Syscall {
            args: [
                0,
                siz,
                0x07, // PROT_READ|PROT_WRITE|PROT_EXEC
                0x22, // MAP_PRIVATE|MAP_ANONYMOUS
                ::std::u64::MAX,
                0,
            ],
            call: 0,
            pid: self.target_pid,
            return_val: 9,
        };
        info!("siz: 0x{:x}, pid: {}", siz, self.target_pid);
        match syscall.dispatch() {
            Ok(ret) => {
                let reti = ret as i64;
                if reti > -4096 && reti < 0 {
                    Err(GenError::RawOsError(-reti as usize))
                } else { Ok(ret) }
            },
            Err(e) => {
                Err(GenError::RawOsError(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate libc;
    use super::Officer;
    use std::env;

    #[test]
    fn officer_new() {
        let pid = fork_and_halt();
        let curr_exec = env::current_exe().unwrap();
        let officer = Officer::new(pid, curr_exec.as_path()).unwrap();
        assert_eq!(officer.target.pid, pid);
        assert_eq!(officer.target.exec_path, curr_exec);
    }

    #[test]
    fn officer_attach_and_release() {
        let pid = fork_and_halt();
        let curr_exec = env::current_exe().unwrap();
        let officer = Officer::new(pid, curr_exec.as_path()).unwrap();
        assert_eq!(officer.attach_target().unwrap(), 0);
        assert_eq!(officer.release_target().unwrap(), 0);
    }

    fn fork_and_halt() -> libc::c_int {
        match unsafe { fork() } {
            0 => { loop { unsafe { raise(19); } } },
            v => v
        }
    }

    extern "C" {
        fn fork() -> libc::pid_t;
        fn raise(signal: libc::c_int) -> libc::c_int;
    }
}
