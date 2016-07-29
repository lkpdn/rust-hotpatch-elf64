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
use std::fmt;

#[macro_use]
pub mod dwarf;
#[macro_use]
pub mod officer;
pub mod ptrace_ext;
use officer::Officer;

#[derive(Debug)]
pub enum GenError {
    RawOsError(usize),
    Plain(String),
    ElfParseError(elf::ParseError),
    StdIoError(std::io::Error),
}

#[derive(Debug)]
pub struct ElfParseError(elf::ParseError);

impl fmt::Display for ElfParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ElfParseError(elf::ParseError::IoError(ref err)) => write!(f, "{}", err),
            ElfParseError(elf::ParseError::InvalidMagic) => write!(f, "{}", "ElfParseError: Invalid magic"),
            ElfParseError(elf::ParseError::InvalidFormat(Some(ref err))) => write!(f, "{}", err),
            ElfParseError(elf::ParseError::InvalidFormat(None)) => write!(f, "{}", "?"),
            ElfParseError(elf::ParseError::NotImplemented) => write!(f, "{}", "ElfParseError: Not implemented"),
        }
    }
}

impl fmt::Display for GenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GenError::RawOsError(ref err) => write!(f, "Raw os error: {}", err),
            GenError::Plain(ref err) => write!(f, "{}", err),
            GenError::ElfParseError(_) => write!(f, "{}", self),
            GenError::StdIoError(ref err) => write!(f, "{}", err),
        }
    }
}

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
