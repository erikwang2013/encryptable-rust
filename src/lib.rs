// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 为敏感字段提供「可检索的匿名化 / 加密」能力：写入数据库前加密，读出时解密，
//! 并可生成与 MySQL / PostgreSQL 兼容的 SQL 片段。
//!
//! 落库加密（不是哈希、不是脱敏）与「按原值查询」通常不可兼得 —— 纯加密库要你
//! 自己写持久层，ORM 方案把你锁进一个框架。这个库把两头补上。
//!
//! ```
//! use encryptable::config::ArrayConfig;
//! use encryptable::AeadEncrypter;
//!
//! let encrypter = AeadEncrypter::new(&ArrayConfig::new(
//!     "0123456789abcdef0123456789abcdef",
//! ))?;
//!
//! let ciphertext = encrypter.encrypt("13800138000")?;
//! assert_eq!(encrypter.decrypt_text(&ciphertext)?, "13800138000");
//! # Ok::<(), encryptable::Error>(())
//! ```
//!
//! # 两条路径
//!
//! | | [`AeadEncrypter`] | [`DbEncrypter`] |
//! |---|---|---|
//! | 密码 | AES-256-GCM（认证） | AES-256-ECB（确定性） |
//! | 密文 | 随机 nonce，同明文两次不同 | 同明文恒定相同 |
//! | 用途 | **默认**，所有存储场景 | 必须在 `WHERE` 里按原值比对的列 |
//! | 风险 | 无 | 频率分析可行，低基数列出卖隐私 |
//!
//! DB 路径只能用 ECB 不是历史包袱：MySQL 的 `AES_DECRYPT` 与 pgcrypto 都只认
//! ECB/CBC，要让**数据库自己**解密就别无选择。两条路径产出的载荷格式不兼容，
//! 各自带格式字节，混用会得到明确的 [`Error::WrongFormat`]。
//!
//! # 密钥轮换
//!
//! 主密钥 + 一串退役密钥组成密钥环，解密时按顺序逐个试 ——
//! 新数据用新主密钥写入，存量数据在退役密钥还在环上时照常读出：
//!
//! ```
//! use encryptable::config::ArrayConfig;
//! use encryptable::AeadEncrypter;
//!
//! let old = AeadEncrypter::new(&ArrayConfig::new(
//!     "0123456789abcdef0123456789abcdef",
//! ))?;
//! let ciphertext = old.encrypt("存量数据")?;
//!
//! // 换主密钥，旧的退进 previous_keys
//! let rotated = AeadEncrypter::new(
//!     &ArrayConfig::new("fedcba9876543210fedcba9876543210")
//!         .with_previous_keys(vec!["0123456789abcdef0123456789abcdef".into()]),
//! )?;
//! assert_eq!(rotated.decrypt_text(&ciphertext)?, "存量数据");   // 还读得出来
//!
//! // 后台任务把存量逐个搬过去，之后就能把旧密钥摘下来
//! let moved = rotated.rotate_to_current_key(&ciphertext)?;
//! assert_eq!(rotated.decrypt_text(&moved)?, "存量数据");
//! # Ok::<(), encryptable::Error>(())
//! ```
//!
//! # 项目宠物：Locky · 小锁灵
//!
//! 钥匙环上那把琥珀色的是当前主密钥，两把灰色的是 [`previous_keys`] ——
//! 还在环上、还能解旧密文，直到你退役它们。
//!
//! 形象是 crate 的一部分，不是文档附件 —— SVG 经 `include_str!` 打进二进制，
//! 所以下游不必依赖本库的文件布局：
//!
//! ```
//! use encryptable::pet;
//!
//! assert_eq!(pet::NAME, "Locky · 小锁灵");
//! assert!(pet::svg().starts_with("<svg"));        // 原始 SVG 标记
//! assert!(pet::ascii().contains("Locky"));        // 终端用的等宽版
//! assert!(pet::data_uri().starts_with("data:image/svg+xml;base64,")); // 塞进 <img src>
//! ```
//!
//! [`previous_keys`]: EncryptableConfig::previous_keys

#![forbid(unsafe_code)]

pub mod cipher;
pub mod config;
pub mod encrypter;
pub mod error;
pub mod guard;
pub mod integrations;
pub mod key;
pub mod pet;
pub mod serializer;
pub mod support;

/// 可选的 serde 集成，只在 `serde` feature 打开时编译。
#[cfg(feature = "serde")]
mod serde_support;

pub use cipher::Cipher;
pub use config::{ArrayConfig, DbDriver, EncryptableConfig, EnvConfig};
pub use encrypter::{AeadEncrypter, DbEncrypter};
pub use error::{Error, Result};
pub use guard::Guard;
pub use integrations::Guarded;
pub use key::{Key, KeyRing};
pub use serializer::Value;
