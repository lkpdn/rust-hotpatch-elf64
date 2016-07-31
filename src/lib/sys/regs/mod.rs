pub mod x86_64;

pub enum Register {
    REG(u8),
    FPREG(u8),
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct REG(pub u8);

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FPREG(pub u8);
