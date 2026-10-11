// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 从代码里直接给出的配置。
//!
//! 对标 PHP 版的 `Encryption::configure([...])` —— 不依赖环境变量、不依赖任何
//! 框架容器的一步式入口。

use zeroize::Zeroizing;

use super::{DbDriver, EncryptableConfig};

/// 由调用方显式构造的配置。
///
/// 密钥与退役密钥用 `Zeroizing` 包裹、`Debug` 输出遮蔽 —— 与 `Key` 同样的待遇：
/// 配置对象活得和进程一样长，不擦就是整个生命周期里都裸着躺在堆上。
///
/// ```no_run
/// use encryptable::config::{ArrayConfig, DbDriver};
///
/// let config = ArrayConfig::new("0123456789abcdef0123456789abcdef")
///     .with_previous_keys(vec!["old-key-old-key-old-key-old-key!".into()])
///     .with_db_driver(DbDriver::Postgres);
/// ```
#[derive(Clone)]
pub struct ArrayConfig {
    key: Option<Zeroizing<String>>,
    cipher: String,
    /// 退役密钥不裹 `Zeroizing`：`EncryptableConfig::previous_keys` 的签名
    /// 返回 `&[String]`，而 `Zeroizing<String>` 与 `String` 是不同类型，
    /// 裹了就得改公共 API。它们在构造期被解析进 [`Key`](crate::key::Key)
    /// 之后就不再用（副本已擦），`Debug` 依然遮蔽。
    previous_keys: Vec<String>,
    db_driver: DbDriver,
}

impl std::fmt::Debug for ArrayConfig {
    /// 手写以遮蔽密钥与退役密钥 —— 否则任何一句 `dbg!(config)` 都会把主密钥
    /// 打进日志。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = if self.key.is_some() {
            "Some(<已遮蔽>)"
        } else {
            "None"
        };
        f.debug_struct("ArrayConfig")
            .field("key", &key)
            .field("cipher", &self.cipher)
            .field(
                "previous_keys",
                &format_args!("{} 把（已遮蔽）", self.previous_keys.len()),
            )
            .field("db_driver", &self.db_driver)
            .finish()
    }
}

impl ArrayConfig {
    /// 默认密码，与 PHP 版一致。单一来源在
    /// [`EncryptableConfig::DEFAULT_CIPHER`]。
    pub const DEFAULT_CIPHER: &'static str = <Self as EncryptableConfig>::DEFAULT_CIPHER;

    /// 给一把主密钥，其余取默认值。
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: Some(Zeroizing::new(key.into())),
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
        self.key.as_ref().map(|k| k.as_str())
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

    /// 配置对象拿着与主密钥等价的东西，检查一下 `Debug` 不吐密钥。
    #[test]
    fn debug_never_leaks_key_material() {
        let c = ArrayConfig::new("0123456789abcdef0123456789abcdef")
            .with_previous_keys(vec!["old-old-old-old-old-old-old-old-".into()]);
        let rendered = format!("{c:?}");
        assert!(!rendered.contains("0123456789abcdef"), "{rendered}");
        assert!(!rendered.contains("old-old"), "{rendered}");
        assert!(rendered.contains("已遮蔽"), "{rendered}");
    }
}
