// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 两条加密路径。
//!
//! - [`AeadEncrypter`] —— 应用侧，随机 nonce 的 AES-GCM。**默认选它。**
//! - [`DbEncrypter`] —— DB 侧，确定性 AES-ECB，外加让数据库自己解密的 SQL 片段。
//!
//! 两者产出的载荷**格式不兼容**，各自带一个格式字节（应用侧 `0x01`、DB 侧 `0x02`）。
//! 把一方的密文喂给另一方会得到明确的 [`Error::WrongFormat`](crate::Error::WrongFormat)，
//! 而不是静默地二次加密。

mod aead;
mod db;

pub use aead::AeadEncrypter;
pub use db::DbEncrypter;

impl AeadEncrypter {
    /// 应用侧载荷的格式字节。
    pub const VERSION: u8 = aead::VERSION;
}

impl DbEncrypter {
    /// DB 侧载荷的格式字节。
    pub const VERSION: u8 = db::VERSION;
}

/// 应用侧与 DB 侧载荷应当互不通用。这条不变量由格式字节保证，这里钉住它。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_formats_are_distinguishable() {
        assert_ne!(AeadEncrypter::VERSION, DbEncrypter::VERSION);
    }
}
