// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 用途子密钥派生（HKDF-SHA256）。
//!
//! # 为什么必须有这一层
//!
//! DB 侧的确定性 ECB 对任意 16 字节明文都给出 `E_K(块)` —— 它是一台**加密
//! 预言机**。若它与 AES-GCM 共用同一把主密钥 K，攻击者可借它取得
//! `E_K(nonce ‖ 计数器)`（GCM 的数据 keystream 与 tag 掩码），乃至
//! `E_K(0^128)`（GHASH 子密钥 H）—— 机密性与完整性被同时拆掉。这不是本库
//! 独有的性质，是「GCM 的密钥必须专用」（NIST SP 800-57）的老要求。
//!
//! 于是主密钥只做一件事：派生。两条路径各拿一把互不可推的子密钥：
//!
//! ```text
//! 子密钥 = HKDF-SHA256(ikm = 主密钥, salt = 空, info = 用途串, L = 密码的密钥长度)
//! 应用侧用途串："encryptable-rust/aead/v1"
//! DB  侧用途串："encryptable-rust/db-ecb/v1"
//! ```
//!
//! 派生是确定性的，任何语言都能复算（Python `HKDF(...)`、`openssl kdf`），
//! 所以运维要手工核对时不必依赖本 crate。密钥环上的每一把钥匙（含
//! `previous_keys`）各派生各的子密钥。
//!
//! # 与旧格式的关系
//!
//! 1.2.x 写出的格式（应用侧 `0x01`、DB 侧 `0x02`）是**主密钥直接**加密的，
//! 双读保留：照旧解得开，但新写入一律用子密钥的新格式（`0x03` / `0x04`）。
//! 存量数据经轮换搬到新格式后，旧格式可以整体退役 —— 那时主密钥才彻底不再
//! 以任何形式接触密文。

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::cipher::Cipher;
use crate::error::{Error, Result};
use crate::key::Key;

/// 应用侧（AEAD）用途串。
pub(crate) const AEAD_INFO: &[u8] = b"encryptable-rust/aead/v1";

/// DB 侧（确定性 ECB）用途串。
pub(crate) const DB_INFO: &[u8] = b"encryptable-rust/db-ecb/v1";

/// 从主密钥派生一把用途子密钥。
///
/// # Errors
///
/// 只可能返回 [`Error::Encrypt`]「输出长度超出上限」—— 而 16/32 字节远在
/// HKDF 的 `255 × HashLen` 上限内，这个分支数学上到不了。不 panic 是为了
/// 守住「库路径里没有 expect」这条底线。
pub(crate) fn derive(master: &Key, info: &[u8], cipher: Cipher) -> Result<Key> {
    let hkdf = Hkdf::<Sha256>::new(None, master.as_bytes());

    // 输出先裹 Zeroizing：它是密钥材料，移交进 Key 之前不该裸着躺在堆上。
    let mut okm = Zeroizing::new(vec![0u8; cipher.key_len()]);
    hkdf.expand(info, &mut okm)
        .map_err(|_| Error::Encrypt("HKDF 输出长度超出上限".into()))?;

    Key::from_bytes(std::mem::take(&mut *okm), cipher)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与 db 模块金标量同一把主密钥。
    const MASTER: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /// 金标量由 Python `cryptography` 的 HKDF 独立复算，并已用 `openssl
    /// enc -aes-256-ecb` 交叉验证子密钥的加密输出逐字节一致。
    #[test]
    fn golden_vectors_match_an_independent_implementation() {
        let master = Key::parse(MASTER, Cipher::Aes256Ecb).unwrap();

        let aead = derive(&master, AEAD_INFO, Cipher::Aes256Gcm).unwrap();
        assert_eq!(
            aead.to_hex().as_str(),
            "b0b748f61e3ab399600457abcb7ba9f6ff47898ba9e6dcc14648e707d7cc3246"
        );

        let db = derive(&master, DB_INFO, Cipher::Aes256Ecb).unwrap();
        assert_eq!(
            db.to_hex().as_str(),
            "a17d9e28145951c875300f13a955288579cf74000125e8eba07772a507db8f94"
        );
    }

    /// 128 位密码派生 16 字节子密钥，且与 256 位的派生结果无关。
    #[test]
    fn key_length_follows_the_cipher() {
        let master16 = Key::parse("000102030405060708090a0b0c0d0e0f", Cipher::Aes128Ecb).unwrap();
        assert_eq!(
            derive(&master16, DB_INFO, Cipher::Aes128Ecb)
                .unwrap()
                .to_hex()
                .as_str(),
            "e2cbb14c7f24e9912e0c38b2ab2a60a0"
        );
        assert_eq!(
            derive(&master16, AEAD_INFO, Cipher::Aes128Gcm)
                .unwrap()
                .to_hex()
                .as_str(),
            "e39b1680131dcedba1d38bc4ba7accb9"
        );
    }

    /// 用途串不同 ⇒ 子密钥不同；而两把子密钥都不等于主密钥本身 ——
    /// 这正是「预言机再也够不着 K」的全部依据。
    #[test]
    fn purposes_are_separated_from_each_other_and_from_the_master() {
        let master = Key::parse(MASTER, Cipher::Aes256Ecb).unwrap();
        let aead = derive(&master, AEAD_INFO, Cipher::Aes256Gcm).unwrap();
        let db = derive(&master, DB_INFO, Cipher::Aes256Ecb).unwrap();

        assert_ne!(aead.as_bytes(), master.as_bytes());
        assert_ne!(db.as_bytes(), master.as_bytes());
        assert_ne!(aead.as_bytes(), db.as_bytes());
    }

    /// 派生是确定性的：同一主密钥两次派生必须同结果（轮换与多实例部署都靠它）。
    #[test]
    fn derivation_is_deterministic() {
        let a = Key::parse(MASTER, Cipher::Aes256Ecb).unwrap();
        let b = Key::parse(MASTER, Cipher::Aes256Ecb).unwrap();
        assert_eq!(
            derive(&a, DB_INFO, Cipher::Aes256Ecb).unwrap().as_bytes(),
            derive(&b, DB_INFO, Cipher::Aes256Ecb).unwrap().as_bytes()
        );
    }
}
