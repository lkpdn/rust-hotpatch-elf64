extern crate phf;

use lib::sys::regs::Register;
use lib::sys::regs::x86_64::*;

#[allow(dead_code)]
static REG_MAPPING: phf::Map<u8, Register> = phf_map! {
    0u8  => REG_RAX,
    1u8  => REG_RDX,
    2u8  => REG_RCX,
    3u8  => REG_RBX,
    4u8  => REG_RSI,
    5u8  => REG_RDI,
    6u8  => REG_RBP,
    7u8  => REG_RSP,
    8u8  => REG_R8,
    9u8  => REG_R9,
    10u8 => REG_R10,
    11u8 => REG_R11,
    12u8 => REG_R12,
    13u8 => REG_R13,
    14u8 => REG_R14,
    15u8 => REG_R15,
/*    16u8 => , */
    17u8 => FPREG_XMM0,
    18u8 => FPREG_XMM1,
    19u8 => FPREG_XMM2,
    20u8 => FPREG_XMM3,
    21u8 => FPREG_XMM4,
    22u8 => FPREG_XMM5,
    23u8 => FPREG_XMM6,
    24u8 => FPREG_XMM7,
    25u8 => FPREG_XMM8,
    26u8 => FPREG_XMM9,
    27u8 => FPREG_XMM10,
    28u8 => FPREG_XMM11,
    29u8 => FPREG_XMM12,
    30u8 => FPREG_XMM13,
    31u8 => FPREG_XMM14,
    32u8 => FPREG_XMM15,
    33u8 => FPREG_ST0,
    34u8 => FPREG_ST1,
    35u8 => FPREG_ST2,
    36u8 => FPREG_ST3,
    37u8 => FPREG_ST4,
    38u8 => FPREG_ST5,
    39u8 => FPREG_ST6,
    40u8 => FPREG_ST7,
    41u8 => REG_MM0,
    42u8 => REG_MM1,
    43u8 => REG_MM2,
    44u8 => REG_MM3,
    45u8 => REG_MM4,
    46u8 => REG_MM5,
    47u8 => REG_MM6,
    48u8 => REG_MM7,
    49u8 => REG_RFLAGS,
    50u8 => REG_ES,
    51u8 => REG_CS,
    52u8 => REG_SS,
    53u8 => REG_DS,
    54u8 => REG_FS,
    55u8 => REG_GS,
    58u8 => REG_FS_BASE,
    59u8 => REG_GS_BASE,
    62u8 => REG_TR,
    63u8 => REG_LDTR,
    64u8 => REG_MXCSR,
    65u8 => REG_FCW,
    66u8 => REG_FSW
};
