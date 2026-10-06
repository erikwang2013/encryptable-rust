// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 从代码里直接给出的配置。
//!
//! 对标 PHP 版的 `Encryption::configure([...])` —— 不依赖环境变量、不依赖任何
//! 框架容器的一步式入口。

use super::{DbDriver, EncryptableConfig};

/// 由调用方显式构造的配置。
///
/// ```no_run
/// use encryptable::config::{ArrayConfig, DbDriver};
///
/// let config = ArrayConfig::new("0123456789abcdef0123456789abcdef")
///     .with_previous_keys(vec!["old-key-old-key-old-key-old-key!".into()])
///     .with_db_driver(DbDriver::Postgres);
/// ```
#[derive(Debug, Clone)]
pub struct ArrayConfig {
    key: Option<String>,
    cipher: String,
    previous_keys: Vec<String>,
    db_driver: DbDriver,
}

impl ArrayConfig {
    /// 默认密码，与 PHP 版一致。
    pub const DEFAULT_CIPHER: &'static str = "aes-256-gcm";

    /// 给一把主密钥，其余取默认值。
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: Some(key.into()),
            ..Self::default()
        }
    }

    /// 覆盖密码。
    ///
    /// 密码是否**可用**由加密器在构造时判定，这里不做校验 —— 同一个配置既要能
    /// 喂给应用侧（只收 AEAD）又要能喂给 DB 侧（只收 ECB），在这里拦会把话说死。
    pub fn with_cipher(mut self, cipher: impl Into<String>) -> Self {
        self.cipher = cipher.into();
        self
    }

    /// 设置退役密钥，只用于解密。顺序：最近退役的放前面。
    pub fn with_previous_keys(mut self, keys: Vec<String>) -> Self {
        self.previous_keys = keys;
        self
    }

    /// 设置 SQL 片段的目标方言。
    pub fn with_db_driver(mut self, driver: DbDriver) -> Self {
        self.db_driver = driver;
        self
    }
}

impl Default for ArrayConfig {
    /// 没有密钥、默认密码、空密钥环、MySQL 方言。
    ///
    /// 密钥留空是允许的 —— 加密器构造时才会报 [`Error::MissingKey`](crate::Error::MissingKey)。
    fn default() -> Self {
        Self {
            key: None,
            cipher: Self::DEFAULT_CIPHER.to_owned(),
            previous_keys: Vec::new(),
            db_driver: DbDriver::default(),
        }
    }
}

impl EncryptableConfig for ArrayConfig {
    fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    fn cipher(&self) -> &str {
        &self.cipher
    }

    fn previous_keys(&self) -> &[String] {
        &self.previous_keys
    }

    fn db_driver(&self) -> DbDriver {
        self.db_driver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_php_package() {
        let c = ArrayConfig::default();
        assert_eq!(c.key(), None);
        assert_eq!(c.cipher(), "aes-256-gcm");
        assert!(c.previous_keys().is_empty());
        assert_eq!(c.db_driver(), DbDriver::Mysql);
    }

    #[test]
    fn builders_override_every_field() {
        let c = ArrayConfig::new("k")
            .with_cipher("aes-256-ecb")
            .with_previous_keys(vec!["p1".into(), "p2".into()])
            .with_db_driver(DbDriver::Postgres);
        assert_eq!(c.key(), Some("k"));
        assert_eq!(c.cipher(), "aes-256-ecb");
        assert_eq!(c.previous_keys(), ["p1", "p2"]);
        assert_eq!(c.db_driver(), DbDriver::Postgres);
    }
}
