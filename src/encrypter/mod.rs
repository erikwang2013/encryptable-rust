// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 两条加密路径。
//!
//! - [`AeadEncrypter`] —— 应用侧，随机 nonce 的 AES-GCM。**默认选它。**
//! - [`DbEncrypter`] —— DB 侧，确定性 AES-ECB，外加让数据库自己解密的 SQL 片段。
//!
//! 两者产出的载荷**格式不兼容**，各自带格式字节（应用侧 `0x03`，旧一代 `0x01`；
//! DB 侧 `0x04`，旧一代 `0x02`）。拿到对方的密文时：
//!
//! - **解密**会得到明确的 [`Error::WrongFormat`](crate::Error::WrongFormat)，
//!   而不是静默产出垃圾；
//! - **DB 侧加密**会拒绝应用侧载荷（带长度闸，短输入不误伤；绕过口是
//!   [`DbEncrypter::seal`](crate::encrypter::DbEncrypter::seal)）；
//! - **应用侧加密**没有对应的免费断言 —— ECB 无认证、形状判定又有假阳性上限，
//!   拦下去会误伤「形状恰好吻合的明文」。所以拿到 DB 侧密文时会把它当普通字符串
//!   照常加密，产出「密文的密文」。别这么干；这条差异是刻意的。

mod aead;
mod db;

pub use aead::AeadEncrypter;
pub use db::DbEncrypter;

impl AeadEncrypter {
    /// 应用侧载荷当前写出的格式字节。
    pub const VERSION: u8 = aead::VERSION;

    /// 应用侧载荷的旧格式字节（1.2.x）。只读。
    pub const LEGACY_VERSION: u8 = aead::LEGACY_VERSION;
}

impl DbEncrypter {
    /// DB 侧载荷当前写出的格式字节。
    pub const VERSION: u8 = db::VERSION;

    /// DB 侧载荷的旧格式字节（1.2.x）。只读。
    pub const LEGACY_VERSION: u8 = db::LEGACY_VERSION;
}

/// 应用侧与 DB 侧载荷应当互不通用。这条不变量由格式字节保证，这里钉住它。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_formats_are_distinguishable() {
        assert_ne!(AeadEncrypter::VERSION, DbEncrypter::VERSION);
        // 四代格式字节两两都不同 —— 分派逻辑靠这一点
        let all = [
            AeadEncrypter::VERSION,
            AeadEncrypter::LEGACY_VERSION,
            DbEncrypter::VERSION,
            DbEncrypter::LEGACY_VERSION,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "格式字节 0x{a:02x} 被两代共用");
            }
        }
    }
}
