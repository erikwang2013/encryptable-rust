// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 配置来源。
//!
//! Rust 里没有 PSR-11 容器，也没有 `config()` / `app()` 这种全局助手，所以
//! PHP 版的「容器 → 回调 → 数组 → 环境变量」四级回退在 Rust 侧塌缩成一件事：
//! 你要么直接构造一个配置，要么用 [`EnvConfig`]。加密器在构造时就把它定下来，
//! 之后不再解析。

mod array;
mod env;

pub use array::ArrayConfig;
pub use env::EnvConfig;

/// SQL 片段要用的数据库方言。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DbDriver {
    /// MySQL / MariaDB，走 `AES_DECRYPT` + `FROM_BASE64`。
    #[default]
    Mysql,
    /// PostgreSQL，走 pgcrypto 的 `decrypt` + `decode`。
    Postgres,
}

impl DbDriver {
    /// 从驱动名推断方言。
    ///
    /// 认 `pgsql` / `postgres` / `postgresql` 三种写法（PHP 版的
    /// `EnvDbDriverDetector` 认的也是这三个），其余一律按 MySQL 处理 ——
    /// 与 PHP 版一致：认不出来时取默认值而不是报错，因为方言错了会立刻在
    /// 数据库上炸，而配置阶段报错会连 MySQL 都跑不起来。
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "pgsql" | "postgres" | "postgresql" => Self::Postgres,
            _ => Self::Mysql,
        }
    }
}

/// 加密器需要知道的全部配置。
///
/// 默认实现给出了开箱可用的取值，所以最小实现只需要覆写 [`key`](Self::key)。
///
/// ```no_run
/// use encryptable::config::EncryptableConfig;
///
/// struct MyConfig;
/// impl EncryptableConfig for MyConfig {
///     fn key(&self) -> Option<&str> { Some("0123456789abcdef0123456789abcdef") }
/// }
/// ```
pub trait EncryptableConfig: Send + Sync {
    /// 主密钥。新密文一律用它产生。
    ///
    /// 允许 `base64:` 前缀，便于存放二进制密钥。
    fn key(&self) -> Option<&str>;

    /// 密码。默认 `aes-256-gcm`。
    ///
    /// **密钥环上的每一把钥匙都必须配得上这个密码** —— 环里存的是裸密钥字节，
    /// 不含各自的密码信息。
    fn cipher(&self) -> &str {
        "aes-256-gcm"
    }

    /// 退役密钥，**只用于解密**。
    ///
    /// 顺序有意义：最近退役的放前面。主密钥试过且失败之后才轮到它们，
    /// 见 [`AeadEncrypter::decrypt`](crate::encrypter::AeadEncrypter::decrypt)。
    fn previous_keys(&self) -> &[String] {
        &[]
    }

    /// SQL 片段的目标方言。默认 MySQL。
    fn db_driver(&self) -> DbDriver {
        DbDriver::Mysql
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_driver_recognizes_the_three_postgres_spellings() {
        for name in [
            "pgsql",
            "postgres",
            "postgresql",
            "PostgreSQL",
            " postgres ",
        ] {
            assert_eq!(DbDriver::from_name(name), DbDriver::Postgres, "{name}");
        }
    }

    #[test]
    fn unknown_drivers_fall_back_to_mysql() {
        for name in ["mysql", "mariadb", "sqlite", "", "oracle"] {
            assert_eq!(DbDriver::from_name(name), DbDriver::Mysql, "{name}");
        }
    }

    #[test]
    fn db_driver_defaults_to_mysql() {
        assert_eq!(DbDriver::default(), DbDriver::Mysql);
    }
}
