// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 从环境变量读配置。
//!
//! 读取动作全部发生在**构造时**，之后配置就是一堆自有字段 —— 进程里再改环境
//! 变量也不会影响已经建好的加密器。这既是可预期的，也顺带避开了「读值读到一半
//! 被别人改了」的竞态。

use zeroize::Zeroizing;

use super::{DbDriver, EncryptableConfig};
use crate::support::previous_keys;

/// 环境变量名，与 PHP 版逐字一致 —— 运维的部署脚本可以照搬。
pub mod vars {
    /// 主密钥。
    pub const KEY: &str = "ENCRYPTION_KEY";
    /// 密码，默认 `aes-256-gcm`。
    pub const CIPHER: &str = "ENCRYPTION_CIPHER";
    /// 退役密钥，逗号分隔。
    pub const PREVIOUS_KEYS: &str = "ENCRYPTION_PREVIOUS_KEYS";
    /// SQL 片段方言，`mysql` / `pgsql` / `postgres`。
    pub const DB_DRIVER: &str = "ENCRYPTION_DB_DRIVER";
}

/// 由环境变量构造的配置。
///
/// 密钥用 `Zeroizing` 包裹、`Debug` 遮蔽 —— 与 `ArrayConfig` 同样的待遇。
#[derive(Clone)]
pub struct EnvConfig {
    key: Option<Zeroizing<String>>,
    cipher: String,
    /// 与 [`ArrayConfig`](super::ArrayConfig) 同理：不裹 `Zeroizing`，
    /// 免得把 `EncryptableConfig::previous_keys` 的 `&[String]` 签名带崩。
    previous_keys: Vec<String>,
    db_driver: DbDriver,
}

impl std::fmt::Debug for EnvConfig {
    /// 手写以遮蔽密钥与退役密钥。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = if self.key.is_some() {
            "Some(<已遮蔽>)"
        } else {
            "None"
        };
        f.debug_struct("EnvConfig")
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

impl Default for EnvConfig {
    /// 等价于 [`EnvConfig::from_env`]，**包括它的 panic 行为**。
    fn default() -> Self {
        Self::from_env()
    }
}

impl EnvConfig {
    /// 读真实进程环境。
    ///
    /// # Panics
    ///
    /// `ENCRYPTION_PREVIOUS_KEYS` 写成 JSON 数组（`["k1","k2"]`）时 panic ——
    /// 那正是 [`from_env_with`](Self::from_env_with) 唯一的失败路径，而这条便捷
    /// 构造器的签名（`-> Self`）没法把错误交给调用方。报错消息会带上真实原因。
    /// 不想冒险的调用点请用 [`from_env_with`](Self::from_env_with)，它是 `Result`。
    ///
    /// （2.0 计划把本方法也改成返回 `Result`，并顺带解决 `Default` 不该失败的问题。）
    pub fn from_env() -> Self {
        Self::from_env_with(|k| std::env::var(k).ok()).unwrap_or_else(|e| {
            panic!("ENCRYPTION_PREVIOUS_KEYS 解析失败：{e}（详见 EnvConfig 文档）")
        })
    }

    /// 用注入的取值函数构造。
    ///
    /// # Errors
    ///
    /// [`Error::Serialize`](crate::Error::Serialize) —— `ENCRYPTION_PREVIOUS_KEYS`
    /// 写成了 JSON 数组（`["k1","k2"]`）。这是**刻意**报错的：按逗号硬拆会得到
    /// `["k1"` 与 `"k2"]` 两把错的密钥，而错密钥在环上是静默失效的 —— 解密会跳过
    /// 它继续试下一把，最后只报「全都失败」，没人看得出真正原因是配置格式。
    ///
    /// 其余环境变量缺省或为空都不算错：密钥缺失留到加密器构造时报，
    /// 密码为空回退默认值。
    ///
    /// # 这个泛型参数
    ///
    /// 这是本模块存在这个泛型参数的**唯一**原因：Rust 2024 里
    /// `std::env::set_var` 是 `unsafe` 的，而它与并发读环境变量的线程存在数据
    /// 竞争 —— 测试并行跑时改进程环境是错的。测试改用 `from_env_with(|k| map.get(k).cloned())`，
    /// 不碰进程环境，也就不需要 `unsafe`，更不需要 `--test-threads=1`。
    pub fn from_env_with<F>(get: F) -> crate::error::Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let key = get(vars::KEY)
            .filter(|v| !v.trim().is_empty())
            .map(Zeroizing::new);

        let cipher = get(vars::CIPHER)
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| ArrayConfig::DEFAULT_CIPHER.to_owned());

        let previous_keys = match get(vars::PREVIOUS_KEYS) {
            Some(raw) => previous_keys::parse(&raw)?,
            None => Vec::new(),
        };

        let db_driver = get(vars::DB_DRIVER)
            .map(|v| DbDriver::from_name(&v))
            .unwrap_or_default();

        Ok(Self {
            key,
            cipher,
            previous_keys,
            db_driver,
        })
    }
}

impl EncryptableConfig for EnvConfig {
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

use super::ArrayConfig;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> crate::error::Result<EnvConfig> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        EnvConfig::from_env_with(|k| map.get(k).cloned())
    }

    #[test]
    fn reads_every_variable() {
        let c = env(&[
            (vars::KEY, "0123456789abcdef0123456789abcdef"),
            (vars::CIPHER, "aes-256-cbc"),
            (vars::PREVIOUS_KEYS, "old1,old2"),
            (vars::DB_DRIVER, "pgsql"),
        ])
        .unwrap();
        assert_eq!(c.key(), Some("0123456789abcdef0123456789abcdef"));
        assert_eq!(c.cipher(), "aes-256-cbc");
        assert_eq!(c.previous_keys(), ["old1", "old2"]);
        assert_eq!(c.db_driver(), DbDriver::Postgres);
    }

    #[test]
    fn cipher_falls_back_to_the_default() {
        assert_eq!(env(&[]).unwrap().cipher(), "aes-256-gcm");
        // 空串等同未设置 —— 与 PHP 版 EnvEncryptableConfig 一致
        assert_eq!(env(&[(vars::CIPHER, "")]).unwrap().cipher(), "aes-256-gcm");
        assert_eq!(
            env(&[(vars::CIPHER, "  ")]).unwrap().cipher(),
            "aes-256-gcm"
        );
    }

    #[test]
    fn missing_or_blank_key_is_none() {
        assert_eq!(env(&[]).unwrap().key(), None);
        assert_eq!(env(&[(vars::KEY, "")]).unwrap().key(), None);
        assert_eq!(env(&[(vars::KEY, "   ")]).unwrap().key(), None);
    }

    #[test]
    fn previous_keys_default_to_empty() {
        assert!(env(&[]).unwrap().previous_keys().is_empty());
        assert!(
            env(&[(vars::PREVIOUS_KEYS, "")])
                .unwrap()
                .previous_keys()
                .is_empty()
        );
    }

    /// JSON 数组在这里就要炸，不能等到解密时才表现为「所有密钥都试过了」。
    #[test]
    fn json_previous_keys_surface_as_an_error() {
        assert!(env(&[(vars::PREVIOUS_KEYS, r#"["a","b"]"#)]).is_err());
    }

    #[test]
    fn unknown_db_driver_falls_back_to_mysql() {
        assert_eq!(
            env(&[(vars::DB_DRIVER, "oracle")]).unwrap().db_driver(),
            DbDriver::Mysql
        );
    }

    /// 读完之后改环境不该有影响 —— 配置是自有字段，不是活的视图。
    #[test]
    fn config_is_a_snapshot_not_a_live_view() {
        let map =
            std::sync::Mutex::new(HashMap::from([(vars::KEY.to_owned(), "first".to_owned())]));
        let c = EnvConfig::from_env_with(|k| map.lock().unwrap().get(k).cloned()).unwrap();
        map.lock()
            .unwrap()
            .insert(vars::KEY.to_owned(), "second".to_owned());
        assert_eq!(c.key(), Some("first"));
    }

    /// `Debug` 不该吐密钥与退役密钥。
    #[test]
    fn debug_never_leaks_key_material() {
        let c = env(&[
            (vars::KEY, "0123456789abcdef0123456789abcdef"),
            (vars::PREVIOUS_KEYS, "old-old-old-old-old-old-old-old-"),
        ])
        .unwrap();
        let rendered = format!("{c:?}");
        assert!(!rendered.contains("0123456789abcdef"), "{rendered}");
        assert!(!rendered.contains("old-old"), "{rendered}");
        assert!(rendered.contains("已遮蔽"), "{rendered}");
    }
}
