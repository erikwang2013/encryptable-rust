// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

//! 密钥解析与密钥环。
//!
//! 密钥进内存后一律套 [`Zeroizing`]，离开作用域即擦除。这挡不住核心转储，
//! 但挡得住「密钥随进程内存被换页到磁盘」和「调试器 dump 到的一坨里正好有明文」。

use zeroize::Zeroizing;

use crate::cipher::Cipher;
use crate::error::{Error, Result};

/// 一把已按密码校验过长度的密钥。
///
/// 密钥字节数在**构造时**就定死：长度不对一律报错，绝不截断也不补零。补零会把
/// 弱口令直接当密钥用（这里没有 KDF、没有盐、没有迭代，拿到密文即可高速爆破）；
/// 截断会让轮换后仍落在相同的前缀密钥上，运维以为换过了其实没换。
#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    bytes: Zeroizing<Vec<u8>>,
}

impl Key {
    /// 从字节构造，并校验长度符合密码要求。
    pub fn from_bytes(bytes: Vec<u8>, cipher: Cipher) -> Result<Self> {
        let expected = cipher.key_len();
        if bytes.len() != expected {
            return Err(Error::KeyLength {
                expected,
                actual: bytes.len(),
                cipher: cipher.to_string(),
            });
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// 解析配置里的密钥字符串。
    ///
    /// 识别顺序（写死成这个顺序，不留歧义）：
    /// 1. `base64:` 前缀 —— 解出后续内容，非法 base64 直接报错而不是退回按字面处理；
    /// 2. 恰好 64 个十六进制字符 —— 按 hex 解（32 字节）；
    /// 3. 其余按字面字节处理，长度必须正好等于密码要求。
    ///
    /// 第 2 条与 PHP 版不同（PHP 只认 `base64:` 和字面量）。加它是因为 SQL 片段
    /// 要把密钥以 hex 嵌进去，让运维手上就能有一份同样的表示。
    pub fn parse(raw: &str, cipher: Cipher) -> Result<Self> {
        let raw = raw.trim();

        if raw.is_empty() {
            return Err(Error::MissingKey);
        }

        if let Some(rest) = raw.strip_prefix("base64:") {
            use base64::Engine as _;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(rest.trim())
                .map_err(|_| Error::InvalidKeyBase64)?;
            return Self::from_bytes(decoded, cipher);
        }

        if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
            let decoded = (0..raw.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&raw[i..i + 2], 16))
                .collect::<std::result::Result<Vec<u8>, _>>()
                .map_err(|_| Error::InvalidKeyBase64)?;
            return Self::from_bytes(decoded, cipher);
        }

        Self::from_bytes(raw.as_bytes().to_vec(), cipher)
    }

    /// 密钥字节。
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 小写十六进制表示，给 SQL 片段用（见 [`DbEncrypter::decrypt_expr`](crate::encrypter::DbEncrypter::decrypt_expr)）。
    ///
    /// 返回 `Zeroizing<String>`：它是主密钥的等价物，不该在堆上留到进程结束。
    pub fn to_hex(&self) -> Zeroizing<String> {
        use std::fmt::Write as _;
        let mut s = Zeroizing::new(String::with_capacity(self.bytes.len() * 2));
        for b in self.bytes.iter() {
            // 写入 String 不会失败，这里只是满足签名
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

impl std::fmt::Debug for Key {
    /// 手写 `Debug` 遮蔽密钥内容 —— 否则任何一句 `dbg!(key)` 或错误信息里的
    /// `{key:?}` 都会把主密钥打进日志。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key(<{} 字节，已遮蔽>)", self.bytes.len())
    }
}

/// 主密钥在前、退役密钥在后的一串密钥。
///
/// 新密文只用主密钥产生；解密时按顺序逐个试，任一成功即可 —— 这就是零停机
/// 轮换的全部机制。这正是项目宠物 [`Locky`](crate::pet) 钥匙环上那三把钥匙。
#[derive(Debug, Clone)]
pub struct KeyRing {
    keys: Vec<Key>,
}

impl KeyRing {
    /// 构造密钥环，顺手去重去空。
    ///
    /// 与主密钥相同的退役密钥会被丢掉：保留它只会让环里多一次注定失败的尝试，
    /// 还会让「轮换到底做没做」变得看不出来。
    pub fn new(primary: Key, previous: Vec<Key>) -> Self {
        let mut keys = vec![primary];
        for k in previous {
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
        Self { keys }
    }

    /// 主密钥。新密文一律用它。
    pub fn primary(&self) -> &Key {
        // 不变量：new() 保证至少有一个元素
        &self.keys[0]
    }

    /// 按「主密钥优先，其后按配置顺序」遍历。
    pub fn iter(&self) -> impl Iterator<Item = &Key> {
        self.keys.iter()
    }

    /// 环上钥匙数量。
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// 环上是否只有主密钥。
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K32: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn parses_literal_key_of_exact_length() {
        let k = Key::parse(K32, Cipher::Aes256Gcm).unwrap();
        assert_eq!(k.as_bytes(), K32.as_bytes());
    }

    #[test]
    fn parses_base64_prefixed_key() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(K32.as_bytes());
        let k = Key::parse(&format!("base64:{b64}"), Cipher::Aes256Gcm).unwrap();
        assert_eq!(k.as_bytes(), K32.as_bytes());
    }

    #[test]
    fn rejects_malformed_base64_prefix() {
        assert_eq!(
            Key::parse("base64:!!!not base64!!!", Cipher::Aes256Gcm),
            Err(Error::InvalidKeyBase64)
        );
    }

    /// 裸 base64 **不是**合法密钥 —— 44 个字符按字面量算就是 44 字节。
    ///
    /// 这条钉住的是一个真实踩过的坑：`openssl rand -base64 32` 的输出正是这个形态，
    /// 44 个字符看着就像一把 32 字节密钥的 base64，粘进配置却会被长度校验拒掉。
    /// 这里刻意**不**去猜「它是不是 base64」—— 一旦开始猜，`0123456789abcdef…`
    /// 这种恰好是合法 base64 的字面量密钥就会被解成别的字节，歧义比便利更贵。
    #[test]
    fn bare_base64_is_not_a_valid_key() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(K32.as_bytes());

        // 44 个字符，看着像那么回事
        assert_eq!(b64.len(), 44);
        let err = Key::parse(&b64, Cipher::Aes256Gcm).unwrap_err();
        assert!(
            matches!(
                err,
                Error::KeyLength {
                    expected: 32,
                    actual: 44,
                    ..
                }
            ),
            "裸 base64 应当以长度错误被拒，实际 {err:?}"
        );

        // 补上前缀就对了
        assert!(Key::parse(&format!("base64:{b64}"), Cipher::Aes256Gcm).is_ok());
    }

    #[test]
    fn parses_64_hex_chars_as_bytes() {
        let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let k = Key::parse(hex, Cipher::Aes256Gcm).unwrap();
        assert_eq!(k.as_bytes()[0], 0x00);
        assert_eq!(k.as_bytes()[31], 0x1f);
        assert_eq!(k.to_hex().as_str(), hex);
    }

    #[test]
    fn empty_key_is_missing_not_short() {
        assert_eq!(Key::parse("", Cipher::Aes256Gcm), Err(Error::MissingKey));
        assert_eq!(Key::parse("   ", Cipher::Aes256Gcm), Err(Error::MissingKey));
    }

    #[test]
    fn wrong_lengths_are_rejected_not_padded_or_truncated() {
        for bad in ["short", &K32[..31], &format!("{K32}extra")] {
            let err = Key::parse(bad, Cipher::Aes256Gcm).unwrap_err();
            assert!(
                matches!(err, Error::KeyLength { expected: 32, .. }),
                "{bad:?} → {err:?}"
            );
        }
        // 16 字节密钥配 256 位密码也必须拒绝：这正是 PHP 版测试里点名的一例
        let k16 = &K32[..16];
        assert!(matches!(
            Key::parse(k16, Cipher::Aes256Gcm),
            Err(Error::KeyLength {
                expected: 32,
                actual: 16,
                ..
            })
        ));
        // 反过来，16 字节密码收 32 字节密钥同样拒绝
        assert!(matches!(
            Key::parse(K32, Cipher::Aes128Gcm),
            Err(Error::KeyLength {
                expected: 16,
                actual: 32,
                ..
            })
        ));
    }

    /// 主密钥重复出现在退役列表里不该占两个位置。
    #[test]
    fn ring_dedupes_and_keeps_order() {
        let primary = Key::parse(K32, Cipher::Aes256Gcm).unwrap();
        let k2 = Key::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Cipher::Aes256Gcm).unwrap();
        let k3 = Key::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Cipher::Aes256Gcm).unwrap();

        let ring = KeyRing::new(
            primary.clone(),
            vec![k2.clone(), primary.clone(), k3.clone(), k2.clone()],
        );
        assert_eq!(ring.len(), 3, "主密钥与 k2 各重复一次，应被去掉");
        let order: Vec<&[u8]> = ring.iter().map(|k| k.as_bytes()).collect();
        assert_eq!(order[0], primary.as_bytes());
        assert_eq!(order[1], k2.as_bytes());
        assert_eq!(order[2], k3.as_bytes());
    }

    #[test]
    fn debug_never_leaks_key_material() {
        let k = Key::parse(K32, Cipher::Aes256Gcm).unwrap();
        let rendered = format!("{k:?}");
        assert!(!rendered.contains(K32), "Debug 泄漏了密钥：{rendered}");
        assert!(rendered.contains("已遮蔽"));
    }
}
