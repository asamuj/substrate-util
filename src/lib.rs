pub mod command;
pub mod generate;
pub mod parse;

pub const PAIR_DIV: [u8; 5] = [161, 35, 3, 33, 0];
/** public/secret start block (generation 1-3, will change in 4, don't rely on value) */
pub const PAIR_HDR: [u8; 16] = [48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32];

pub const SALT_LENGTH: u8 = 32;
