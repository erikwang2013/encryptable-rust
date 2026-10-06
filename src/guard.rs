// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 请求守卫：交给处理器的一个共享加密句柄。
//!
//! 框架集成层（axum / actix-web / rocket / poem / salvo / warp / bee-rust / e-cat）
//! 全都在这一层之上做薄适配 —— 把 [`Guard`] 按各自框架的惯例注入请求上下文，
//! 处理器拿到它就能加解密，不必把配置或加密器一路透传下去。
//!
//! ```no_run
//! use encryptable::guard::Guard;
//! use encryptable::config::ArrayConfig;
//!
//! let guard = Guard::new(&ArrayConfig::new("0123456789abcdef0123456789abcdef"))?;
//!
//! // 处理器里
//! let stored = guard.encrypt("13800138000")?;
//! assert_eq!(guard.decrypt_text(&stored)?, "13800138000");
//! # Ok::<(), encryptable::Error>(())
//! ```
//!
//! # 为什么是 `Arc`
//!
//! 每个请求都要拿到同一个加密器，而框架普遍要求注入的状态是 `Send + Sync + 'static`
//! 且常常要求 `Clone`。加密器本身是只读的、构造后不再变，所以 `Arc` 共享即可 ——
//! 密钥环只在构造时解析一次，每请求零成本。

use std::sync::Arc;

use crate::config::{EncryptableConfig, EnvConfig};
use crate::encrypter::{AeadEncrypter, DbEncrypter};
use crate::error::Result;
use crate::serializer::Value;

/// 请求守卫：一个可跨请求共享、可跨线程克隆的加密句柄。
///
/// 应用侧加密器是必需的；DB 侧是可选的 —— 它要求确定性密码，而一个部署里
/// 往往只有少数列需要它。
#[derive(Clone)]
pub struct Guard {
    aead: Arc<AeadEncrypter>,
    db: Option<Arc<DbEncrypter>>,
}

impl Guard {
    /// 只带应用侧加密器 —— 最常见的情形。
    ///
    /// 构造时即完成校验（密钥长度、密码是否可用），配置错了就在启动时炸。
    pub fn new<C: EncryptableConfig + 'static>(config: &C) -> Result<Self> {
        Ok(Self {
            aead: Arc::new(AeadEncrypter::new(config)?),
            db: None,
        })
    }

    /// 从一个已经建好的应用侧加密器构造。
    pub fn from_aead(aead: AeadEncrypter) -> Self {
        Self {
            aead: Arc::new(aead),
            db: None,
        }
    }

    /// 从环境变量构造（`ENCRYPTION_*`）。
    pub fn from_env() -> Result<Self> {
        Self::new(&EnvConfig::from_env())
    }

    /// 再挂上 DB 侧加密器。
    ///
    /// 单独传一份配置，因为 DB 侧要求确定性密码，与常驻的 `aes-256-gcm` 不同。
    /// 密钥可以复用同一把（`aes-256-*` 的长度都是 32 字节），但密码必须显式写
    /// 成 `aes-256-ecb` 或 `aes-128-ecb` —— 这里不做隐式替换，免得「为什么它
    /// 用的是另一个密码」变成一个只有读源码才知道的事。
    pub fn with_db<C: EncryptableConfig + 'static>(mut self, config: &C) -> Result<Self> {
        self.db = Some(Arc::new(DbEncrypter::new(config)?));
        Ok(self)
    }

    /// 挂上一个已经建好的 DB 侧加密器。
    pub fn with_db_encrypter(mut self, db: DbEncrypter) -> Self {
        self.db = Some(Arc::new(db));
        self
    }

    /// 应用侧加密器。总是存在。
    pub fn aead(&self) -> &AeadEncrypter {
        &self.aead
    }

    /// DB 侧加密器，没挂则 `None`。
    pub fn db(&self) -> Option<&DbEncrypter> {
        self.db.as_deref()
    }

    /// 是否挂了 DB 侧加密器。
    pub fn has_db(&self) -> bool {
        self.db.is_some()
    }

    /// 加密一个值（转发到应用侧）。
    pub fn encrypt(&self, value: impl Into<Value>) -> Result<String> {
        self.aead.encrypt(value)
    }

    /// 解密（转发到应用侧）。
    pub fn decrypt(&self, payload: &str) -> Result<Value> {
        self.aead.decrypt(payload)
    }

    /// 解密并断言是字符串。
    pub fn decrypt_text(&self, payload: &str) -> Result<String> {
        self.aead.decrypt_text(payload)
    }

    /// 宽松解密：解不开就原样返回。见
    /// [`AeadEncrypter::decrypt_or_original`]。
    pub fn decrypt_or_original(&self, payload: &str) -> String {
        self.aead.decrypt_or_original(payload)
    }

    /// 廉价形状判定。
    pub fn is_encrypted(&self, value: &str) -> bool {
        self.aead.is_encrypted(value)
    }

    /// 用当前主密钥重新加密（轮换用）。
    pub fn rotate_to_current_key(&self, payload: &str) -> Result<String> {
        self.aead.rotate_to_current_key(payload)
    }

    /// 环上钥匙数量（含主密钥）。
    pub fn ring_len(&self) -> usize {
        self.aead.ring_len()
    }
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("aead", &self.aead)
            .field("db", &self.db)
            .finish()
    }
}

/// 编译期确认：框架普遍要求注入的状态满足这几个界。
///
/// 不满足的话每个框架适配层都得包一层 `Mutex`，那会让每请求多一次锁 ——
/// 所以这里把它钉死成硬约束。
const _: () = {
    const fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<Guard>();
    assert_send_sync::<AeadEncrypter>();
    assert_send_sync::<DbEncrypter>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use crate::config::{ArrayConfig, DbDriver};

    const K32: &str = "0123456789abcdef0123456789abcdef";

    fn guard() -> Guard {
        Guard::new(&ArrayConfig::new(K32)).unwrap()
    }

    #[test]
    fn round_trips_through_the_guard() {
        let g = guard();
        let c = g.encrypt("13800138000").unwrap();
        assert_eq!(g.decrypt_text(&c).unwrap(), "13800138000");
        assert!(g.is_encrypted(&c));
    }

    #[test]
    fn db_side_is_absent_until_attached() {
        let g = guard();
        assert!(!g.has_db());
        assert!(g.db().is_none());

        let g = g
            .with_db(&ArrayConfig::new(K32).with_cipher("aes-256-ecb"))
            .unwrap();
        assert!(g.has_db());
        assert_eq!(g.db().unwrap().cipher_name(), "aes-256-ecb");
    }

    /// DB 侧密钥可以与主密钥相同 —— `aes-256-*` 都是 32 字节。
    #[test]
    fn both_sides_share_one_key_but_not_one_cipher() {
        let g = Guard::new(&ArrayConfig::new(K32))
            .unwrap()
            .with_db(&ArrayConfig::new(K32).with_cipher("aes-256-ecb"))
            .unwrap();

        assert_eq!(g.aead().cipher_name(), "aes-256-gcm");
        assert_eq!(g.db().unwrap().cipher_name(), "aes-256-ecb");
    }

    /// 配置错了就该在**构造时**炸，而不是在某个请求路径上。
    #[test]
    fn bad_config_fails_at_construction() {
        assert!(matches!(
            Guard::new(&ArrayConfig::default()),
            Err(Error::MissingKey)
        ));
        assert!(matches!(
            Guard::new(&ArrayConfig::new(K32).with_cipher("rc4")),
            Err(Error::UnsupportedCipher(_))
        ));
        // 非 ECB 密码挂 DB 侧也要当场被拒
        assert!(matches!(
            Guard::new(&ArrayConfig::new(K32))
                .unwrap()
                .with_db(&ArrayConfig::new(K32).with_cipher("aes-256-gcm")),
            Err(Error::CipherNotUsable { .. })
        ));
    }

    /// 克隆出来的守卫共享同一份密钥环，密文互通。
    #[test]
    fn clones_share_the_same_encrypter() {
        let g = guard();
        let c = g.encrypt("x").unwrap();

        let cloned = g.clone();
        assert_eq!(cloned.decrypt_text(&c).unwrap(), "x");

        // 另一个守卫带上了退役密钥，也能解开同一个密文
        let rotated = Guard::new(
            &ArrayConfig::new("fedcba9876543210fedcba9876543210")
                .with_previous_keys(vec![K32.into()]),
        )
        .unwrap();
        assert_eq!(rotated.decrypt_text(&c).unwrap(), "x");
    }

    /// 守卫要能跨线程用 —— 这是所有框架适配层的前提。
    #[test]
    fn guard_is_usable_across_threads() {
        let g = guard();
        let c = g.encrypt("跨线程").unwrap();

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let g = g.clone();
                let c = c.clone();
                std::thread::spawn(move || g.decrypt_text(&c).unwrap())
            })
            .collect();

        for h in handles {
            assert_eq!(h.join().unwrap(), "跨线程");
        }
    }

    #[test]
    fn rotate_forwards_to_the_aead_encrypter() {
        let g = guard();
        let c = g.encrypt("数据").unwrap();
        let moved = g.rotate_to_current_key(&c).unwrap();
        assert_eq!(g.decrypt_text(&moved).unwrap(), "数据");
    }

    #[test]
    fn from_aead_and_with_db_encrypter_build_the_same_shape() {
        let aead = AeadEncrypter::new(&ArrayConfig::new(K32)).unwrap();
        let db = DbEncrypter::new(&ArrayConfig::new(K32).with_cipher("aes-256-ecb")).unwrap();

        let g = Guard::from_aead(aead).with_db_encrypter(db);
        assert!(g.has_db());
        assert_eq!(g.db().unwrap().driver(), DbDriver::Mysql);
    }

    /// 密钥不该从 `Debug` 里漏出去。
    #[test]
    fn debug_never_leaks_the_key() {
        let s = format!("{:?}", guard());
        assert!(!s.contains(K32), "{s}");
    }
}
