#![feature(pattern, slice_patterns, trace_macros, inclusive_range_syntax, range_contains, core_intrinsics)]
#[macro_use(read_u64)]
extern crate elf;
extern crate getopts;
extern crate regex;
extern crate libc;
extern crate byteorder;
#[macro_use]
extern crate log;
extern crate env_logger;
use getopts::Options;
use regex::Regex;
use std::env;
use std::path::PathBuf;
use std::io;
pub mod util;
use util::GenError;

#[macro_use]
pub mod officer;
use officer::Officer;
#[macro_use]
pub mod lib;
use lib::dwarf::*;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
    println!("{}", r#"
Stdin or interactive mode:
    * dl {{so path}} as {{so label}}
    * replace {{orig func}} with {{so label}}:{{new func}}
"#);
}

fn main() {
    env_logger::init().unwrap();

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.reqopt("p", "pid", "[required] set target pid", "NUM");
    opts.reqopt("t", "target", "[required] target binary path", "FILE");
    opts.optflag("h", "help", "print this help menu");
    opts.optopt("", "so-path", "injected shared object path", "FILE");
    opts.optopt("", "target-source", "assumed target source file path", "FILE");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m },
        Err(e) => {
            println!("{}", e.to_string());
            print_usage(&program, opts);
            return
        }
    };

    if matches.opt_present("h") { print_usage(&program, opts); return }
    let pid = match matches.opt_str("p").unwrap().parse::<i32>() {
        Ok(p) => { p },
        Err(e) => {
            println!("{}", e.to_string());
            print_usage(&program, opts);
            return
        }
    };
    let target = matches.opt_str("t").unwrap();
    let _so_path = matches.opt_str("so-path").unwrap_or("".to_string());
    let target_source = matches.opt_str("target-source").unwrap_or(String::new());
    let _path = PathBuf::from(&target);

    let mut officer = Officer::from_pid(pid).unwrap();
    officer.attach_target().expect("cannot attach");
    if !target_source.is_empty() {
        let _ = officer.set_target_source(target_source)
          .map_err(|e| println!("{}", e));
    }

    let ops = vec![
        Regex::new(r"^dl (?P<so_path>\S+) as (?P<label>\S+)").unwrap(),
        Regex::new(r"^replace (?P<orig_func>\S+) with (?P<label>\S+):(?P<new_func>\S+)").unwrap(),
        Regex::new(r"^set target_source (?P<target_source>").unwrap(),
    ];
    let mut buffer = String::new();
    'loop_line: while io::stdin().read_line(&mut buffer).unwrap() > 0 {
        for (i, op) in ops.iter().enumerate() {
            match op.captures(&*buffer) {
                Some(cap) => {
                    if i == 0 {
                        let path = cap.name("so_path").unwrap_or("").to_string();
                        let label = cap.name("label").unwrap_or("").to_string();
                        info!("dl {} as {}", path, label);
                        let idx = officer.add_parasite(path, label);
                        let _ = officer.dl(idx);
                    } else if i == 1 {
                        let orig_func = cap.name("orig_func").unwrap_or("").to_string();
                        let label = cap.name("label").unwrap_or("").to_string();
                        let new_func = cap.name("new_func").unwrap_or("").to_string();
                        info!("replace {} with {}:{}", orig_func, label, new_func);
                        let _ = officer.put_on_trampoline(orig_func, label, new_func)
                          .map_err(|e| println!("{}", e));
                    } else if i == 2 {
                        let target_source = cap.name("target_source").unwrap_or("").to_string();
                        let _ = officer.set_target_source(target_source)
                          .map_err(|e| println!("{}", e));
                    }
                },
                None => continue,
            }
            buffer.clear();
            continue 'loop_line;
        }
        buffer.clear();
    };
    officer.release_target().expect("cannot release");
}

pub fn try_on_dwarf(filepath: String, _var_name: String, filename: String)
  -> Result<u64, GenError> {
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
    if result.len() > 1 { Err(GenError::Plain("cannot choose appropriate one".to_string())) }
    else if result.len() == 1 { Ok(result[0]) }
    else { Err(GenError::Plain("it was a fruitless try".to_string())) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    #[test]
    fn test_try_on_dwarf() {
        let filepath = String::from("./files/c/build/test1");
        let var_name = String::from("s_buf");
        let filename = String::from("test1.c");
        Command::new("/usr/bin/make")
          .current_dir("./files/c")
          .arg("all")
          .status()
          .expect("failed to make");
        assert_eq!(try_on_dwarf(filepath, var_name, filename).unwrap(), 0x601050);
    }
}
