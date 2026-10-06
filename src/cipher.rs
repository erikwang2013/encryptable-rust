// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 密码白名单与它们的性质。
//!
//! 白名单而不是透传给 OpenSSL：密码名进不了 SQL 片段与配置诊断，让拼写错误
//! 在解析处就炸掉，比等到解密时才失败要好。

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};

/// 支持的块密码。
///
/// 这些名字与 PHP 版 `openssl_*` 接受的名字逐字一致 —— 配置在两个生态之间
/// 可以照抄，虽然**密文**不互通（Rust 版用了自己的信封）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// AES-256-GCM，带认证，推荐默认。
    Aes256Gcm,
    /// AES-128-GCM，带认证。
    Aes128Gcm,
    /// AES-256-CBC，无认证，仅为兼容既有配置而保留。
    Aes256Cbc,
    /// AES-128-CBC，无认证。
    Aes128Cbc,
    /// AES-256-ECB，确定性 —— 唯一能配合 DB 侧 SQL 片段使用的模式。
    Aes256Ecb,
    /// AES-128-ECB，确定性。
    Aes128Ecb,
}

impl Cipher {
    /// 全部白名单成员，按名称排序，给诊断信息用。
    pub const ALL: [Cipher; 6] = [
        Cipher::Aes128Cbc,
        Cipher::Aes128Ecb,
        Cipher::Aes128Gcm,
        Cipher::Aes256Cbc,
        Cipher::Aes256Ecb,
        Cipher::Aes256Gcm,
    ];

    /// 规范名（小写）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Cbc => "aes-256-cbc",
            Self::Aes128Cbc => "aes-128-cbc",
            Self::Aes256Ecb => "aes-256-ecb",
            Self::Aes128Ecb => "aes-128-ecb",
        }
    }

    /// 该密码要求的密钥字节数：`128` 系 16 字节，`256` 系 32 字节。
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes128Cbc | Self::Aes128Ecb => 16,
            Self::Aes256Gcm | Self::Aes256Cbc | Self::Aes256Ecb => 32,
        }
    }

    /// 是否带认证（AEAD）。只有 AEAD 能检出密文被篡改。
    pub fn is_aead(self) -> bool {
        matches!(self, Self::Aes256Gcm | Self::Aes128Gcm)
    }

    /// 是否确定性：同明文恒定产出同密文。
    ///
    /// 确定性是 ECB 唯一的用处，也是它唯一的代价 —— 相同明文在库里长得一样，
    /// 于是频率分析可行。只为「必须能按原值查询」的列启用。
    pub fn is_deterministic(self) -> bool {
        matches!(self, Self::Aes256Ecb | Self::Aes128Ecb)
    }

    /// 该密码的分组长度，恒为 16。
    pub const BLOCK_LEN: usize = 16;
}

impl FromStr for Cipher {
    type Err = Error;

    /// 大小写不敏感，与 PHP 版一致（PHP 会把配置值先 `strtolower`）。
    fn from_str(s: &str) -> Result<Self> {
        let lower = s.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|c| c.as_str() == lower)
            .ok_or(Error::UnsupportedCipher(s.to_owned()))
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_whitelist_members() {
        for c in Cipher::ALL {
            assert_eq!(Cipher::from_str(c.as_str()).unwrap(), c);
        }
    }

    #[test]
    fn parsing_is_case_and_space_insensitive() {
        assert_eq!(
            Cipher::from_str("  AES-256-GCM ").unwrap(),
            Cipher::Aes256Gcm
        );
        assert_eq!(Cipher::from_str("Aes-128-Ecb").unwrap(), Cipher::Aes128Ecb);
    }

    #[test]
    fn rejects_non_whitelist_ciphers() {
        // PHP 版的测试里点名拒绝的就是这几个
        for bad in ["des-ecb", "rc4", "aes-192-gcm", "", "chacha20-poly1305"] {
            assert!(
                matches!(Cipher::from_str(bad), Err(Error::UnsupportedCipher(_))),
                "{bad} 不该被接受"
            );
        }
    }

    #[test]
    fn key_len_follows_the_128_256_split() {
        assert_eq!(Cipher::Aes128Gcm.key_len(), 16);
        assert_eq!(Cipher::Aes256Gcm.key_len(), 32);
        assert_eq!(Cipher::Aes128Cbc.key_len(), 16);
        assert_eq!(Cipher::Aes256Ecb.key_len(), 32);
    }

    #[test]
    fn aead_and_deterministic_are_disjoint() {
        for c in Cipher::ALL {
            assert!(!(c.is_aead() && c.is_deterministic()), "{c} 两者兼具");
        }
        assert!(Cipher::Aes256Gcm.is_aead());
        assert!(Cipher::Aes256Ecb.is_deterministic());
        // CBC 两边都不占
        assert!(!Cipher::Aes256Cbc.is_aead() && !Cipher::Aes256Cbc.is_deterministic());
    }
}
