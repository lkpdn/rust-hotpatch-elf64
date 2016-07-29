extern crate elf;
use std::io;
use std::fmt;

#[derive(Debug)]
pub enum GenError {
    RawOsError(usize),
    Plain(String),
    ElfParseError(elf::ParseError),
    StdIoError(io::Error),
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
