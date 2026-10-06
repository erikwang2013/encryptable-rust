// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 错误类型。
//!
//! 手写 `Display` 而不引入 `thiserror`：变体只有十来个，而本 crate 的
//! `[dependencies]` 想锁在密码学原语 + base64 上 —— 与 security-rust 的
//! 极简取向一致。`druid-util::crypto` 的 `CryptoError` 也是这么写的。

use std::fmt;

/// crate 统一返回类型。
pub type Result<T> = std::result::Result<T, Error>;

/// encryptable 的全部失败形态。
///
/// 对照 PHP 版的 6 个异常类，这里塌缩成一个枚举 —— `match` 能穷尽，
/// 调用方不必为「该 catch 哪一个」翻文档。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// 没有配置密钥（PHP `MissingEncryptionKeyException`）。
    MissingKey,
    /// 密钥带 `base64:` 前缀但内容不是合法 base64。
    InvalidKeyBase64,
    /// 密钥字节数与密码要求的长度不符。
    ///
    /// 长度不符一律报错，**绝不截断或补零**：补零会把弱口令直接当密钥用，
    /// 而这里没有 KDF / 盐 / 迭代，拿到密文即可高速爆破；截断会让轮换后
    /// 仍落在相同的前缀密钥上，运维误以为已经换过了。
    KeyLength {
        /// 该密码要求的字节数。
        expected: usize,
        /// 实际拿到的字节数。
        actual: usize,
        /// 触发该要求的密码名，例如 `aes-256-gcm`。
        cipher: String,
    },
    /// 没有配置密码。
    MissingCipher,
    /// 配置了白名单以外的密码。
    UnsupportedCipher(String),
    /// 该加密器不支持这个密码 —— 例如把 `aes-256-cbc` 配给应用侧（只收 AEAD），
    /// 或把 `aes-256-gcm` 配给 DB 侧（只收确定性 ECB）。
    CipherNotUsable {
        /// 密码名。
        cipher: String,
        /// 该加密器接受的密码集合，人类可读。
        accepted: &'static str,
        /// 为什么这么限制。
        reason: &'static str,
    },
    /// 加密失败。
    Encrypt(String),
    /// 解密失败：base64 非法、版本字节陌生、认证 tag 不通过，或密钥环全部落空。
    Decrypt(String),
    /// base64 编解码失败。
    Base64(String),
    /// 值无法进类型信封（PHP `SerializationException`）。
    Serialize(String),
    /// 载荷无法出类型信封 —— 类型字节陌生，或字节数与该类型不符（PHP `UnserializationException`）。
    Unserialize(String),
    /// SQL 片段的列名不是合法标识符（注入防护）。
    InvalidColumnRef(String),
    /// 载荷是**另一种**格式的密文 —— 拿应用侧的载荷去解 DB 侧的列，或反之。
    ///
    /// 两个格式各有版本字节（应用侧 `0x01`、DB 侧 `0x02`），所以这里能立刻分辨
    /// 出来，而不是等到解密失败。没有这道闸，把应用侧密文塞进 DB 列会被当成
    /// 明文**再加密一遍**，静默产生解不开的数据。
    WrongFormat {
        /// 实际看到的格式字节。
        found: u8,
        /// 这个加密器期望的格式字节。
        expected: u8,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKey => write!(f, "没有配置加密密钥"),
            Self::InvalidKeyBase64 => write!(f, "加密密钥的 base64 内容非法"),
            Self::KeyLength {
                expected,
                actual,
                cipher,
            } => write!(
                f,
                "密码 [{cipher}] 要求 {expected} 字节密钥，实际 {actual} 字节"
            ),
            Self::MissingCipher => write!(f, "没有配置加密密码"),
            Self::UnsupportedCipher(c) => write!(f, "不支持的加密密码 [{c}]"),
            Self::CipherNotUsable {
                cipher,
                accepted,
                reason,
            } => write!(
                f,
                "密码 [{cipher}] 不能用于此处：只接受 {accepted} —— {reason}"
            ),
            Self::Encrypt(m) => write!(f, "加密失败：{m}"),
            Self::Decrypt(m) => write!(f, "解密失败：{m}"),
            Self::Base64(m) => write!(f, "base64 编解码失败：{m}"),
            Self::Serialize(m) => write!(f, "无法序列化：{m}"),
            Self::Unserialize(m) => write!(f, "无法反序列化：{m}"),
            Self::InvalidColumnRef(c) => {
                write!(f, "非法的列引用 [{c}]：需要匹配 ^[A-Za-z_][A-Za-z0-9_.]*$")
            }
            Self::WrongFormat { found, expected } => write!(
                f,
                "载荷格式不匹配：看到 0x{found:02x}，此处需要 0x{expected:02x} \
                 —— 应用侧与应用侧、DB 侧与 DB 侧的密文不可混用"
            ),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    /// 每个变体都要能渲染成人话，且 `source()` 保持 None（无嵌套原因）。
    #[test]
    fn every_variant_displays() {
        let all = [
            Error::MissingKey,
            Error::InvalidKeyBase64,
            Error::KeyLength {
                expected: 32,
                actual: 16,
                cipher: "aes-256-gcm".into(),
            },
            Error::MissingCipher,
            Error::UnsupportedCipher("rc4".into()),
            Error::CipherNotUsable {
                cipher: "aes-256-cbc".into(),
                accepted: "aes-256-gcm, aes-128-gcm",
                reason: "应用侧只做 AEAD",
            },
            Error::Encrypt("boom".into()),
            Error::Decrypt("tag mismatch".into()),
            Error::Base64("bad pad".into()),
            Error::Serialize("array".into()),
            Error::Unserialize("tag 0x09".into()),
            Error::InvalidColumnRef("x; DROP".into()),
            Error::WrongFormat {
                found: 0x01,
                expected: 0x02,
            },
        ];
        for e in &all {
            let s = e.to_string();
            assert!(!s.is_empty(), "{e:?} 渲染为空");
            assert!(std::error::Error::source(e).is_none());
        }
    }

    /// 关键诊断信息不能丢：长度错误必须同时给出期望值与实际值。
    #[test]
    fn key_length_names_both_numbers() {
        let s = Error::KeyLength {
            expected: 32,
            actual: 16,
            cipher: "aes-256-gcm".into(),
        }
        .to_string();
        assert!(
            s.contains("32") && s.contains("16") && s.contains("aes-256-gcm"),
            "{s}"
        );
    }
}
